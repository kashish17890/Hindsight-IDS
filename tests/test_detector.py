from fastapi.testclient import TestClient
from app.detector import analyze, parse_events, bursts, _norm
from app.generator import generate, FIELDS
from app.main import app
import csv, io


def run():
    ev, lab = generate()
    return analyze([_norm(e) for e in ev], lab)


def test_attack_chain_found_with_full_kill_chain():
    res, _ = run()
    inc = res["incidents"][0]
    assert inc["severity"] == "critical" and "alice" in inc["users"] and "203.0.113.77" in inc["ips"]
    assert len(inc["stages"]) == 7


def test_precision_recall_on_labelled_data():
    res, _ = run()
    assert res["eval"]["precision"] == 1.0 and res["eval"]["recall"] == 1.0


def test_benign_decoys_do_not_become_incidents():
    res, _ = run()
    flagged = {u for i in res["incidents"] for u in i["users"]}
    assert not flagged & {"bob", "carol", "svc_backup", "user10"}
    reasons = " ".join(s["reason"] for s in res["suppressed"])
    assert "plausible travel" in reasons and "scheduled job" in reasons and "typos" in reasons


def test_bursts_threshold():
    mk = lambda ts: [{"t": t} for t in ts]
    assert bursts(mk(range(0, 90, 10)), 300, 10) == []          # 9 events: below threshold
    assert len(bursts(mk(range(0, 100, 10)), 300, 10)) == 1      # 10 events: fires


def test_parsers_csv_jsonl_syslog():
    ev, lab = generate()
    buf = io.StringIO(); w = csv.DictWriter(buf, FIELDS); w.writeheader(); w.writerows(ev[:50])
    assert len(parse_events(buf.getvalue())[0]) == 50
    assert len(parse_events('{"ts":"2026-01-01T00:00:00Z","user":"a","ip":"1.1.1.1","event":"login","outcome":"fail"}\nnot json')[0]) == 1
    sy = "Oct  3 01:00:01 vpn01 sshd[22]: Failed password for invalid user admin from 1.2.3.4 port 22 ssh2"
    e, errs = parse_events(sy)
    assert e[0]["user"] == "admin" and e[0]["outcome"] == "fail" and errs == 0


def test_empty_and_garbage_input_is_safe():
    assert analyze([])[0]["summary"]["events"] == 0
    c = TestClient(app)
    assert c.post("/api/analyze", files={"file": ("x.log", b"garbage\nmore garbage")}).status_code == 400


def test_api_flow():
    c = TestClient(app)
    r = c.get("/api/demo").json()
    assert r["summary"]["incidents"] == 2
    a = next(a for a in r["alerts"] if a["n_evidence"] >= 3)
    ids = ",".join(map(str, a["evidence"][:3]))
    assert len(c.get(f"/api/events?ids={ids}").json()) == 3
    assert "What happened" in c.get("/api/report/1?fmt=md").text
    assert c.get("/api/report/99").status_code == 404


def test_report_formats():
    c = TestClient(app); c.get("/api/demo")
    for fmt, magic in [("pdf", b"%PDF"), ("docx", b"PK"), ("html", b"<!doctype"), ("md", b"# "), ("json", b"{"), ("csv", b"incident")]:
        r = c.get(f"/api/report/0?fmt={fmt}")
        assert r.status_code == 200 and r.content.startswith(magic), fmt
    assert c.get("/api/report/1?fmt=exe").status_code == 400


def test_more_upload_types():
    import openpyxl
    from app.detector import parse_file
    wb = openpyxl.Workbook(); ws = wb.active
    ws.append(["Timestamp", "Username", "src_ip", "Action", "Status"]); ws.append(["2026-10-03 01:00:00", "bob", "1.2.3.4", "logon", "Failed"])
    b = io.BytesIO(); wb.save(b)
    e, _ = parse_file("logs.xlsx", b.getvalue())
    assert e[0]["user"] == "bob" and e[0]["event"] == "login" and e[0]["outcome"] == "fail"
    ap = '1.2.3.4 - - [03/Oct/2026:01:00:00 +0000] "GET /admin HTTP/1.1" 404 120'
    assert parse_file("access.log", ap.encode())[0][0]["source"] == "web"
    assert parse_file("x.txt", b"time\tuser\tip\toutcome\n2026-10-03 01:00:00\tbob\t1.1.1.1\tfailed")[0][0]["outcome"] == "fail"
    try: parse_file("old.xls", b"x"); assert False
    except ValueError: pass
