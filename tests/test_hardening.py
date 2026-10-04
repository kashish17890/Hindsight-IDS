import io, random, datetime as dt, json
import pytest
from fastapi.testclient import TestClient
from app import main, store, autotriage
from app.detector import analyze, parse_events, parse_file, NeedMapping, adapt, _norm
from app.generator import generate

HDR = "ts,source,host,user,ip,event,outcome,country,detail,bytes"
T = lambda s: (dt.datetime(2026, 10, 3, tzinfo=dt.timezone.utc) + dt.timedelta(seconds=s)).strftime("%Y-%m-%dT%H:%M:%SZ")
F = lambda s, user="bob", ip="9.9.9.9", out="fail", c="IN": f"{T(s)},auth,vpn01,{user},{ip},login,{out},{c},,0"
def ana(rows, hdr=HDR): return analyze(parse_events(hdr + "\n" + "\n".join(rows))[0])[0]
def rules(res): return {a["rule"] for a in res["alerts"]}
NOISE = [F(i * 60, f"u{i % 5}", f"10.0.0.{i % 5}", "success") for i in range(400)]  # normal background


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "DB", str(tmp_path / "t.db")); monkeypatch.delenv("HINDSIGHT_LLM_PROVIDER", raising=False); monkeypatch.delenv("HINDSIGHT_LLM_API_KEY", raising=False)
    main.STATE.update(res=None, evs=[], runs={}); main._HITS.clear()
    return TestClient(main.app)


def test_low_and_slow_bruteforce_detected_without_burst_alarm():
    r = ana([F(i * 3600) for i in range(20)] + NOISE)
    assert "low_slow_bruteforce" in rules(r) and "brute_force" not in rules(r)


def test_distributed_attack_on_one_account():
    assert "distributed_attack" in rules(ana([F(i * 20, "alice", f"8.8.{i % 8}.1") for i in range(16)] + NOISE))


def test_clock_skew_order_and_mixed_timezones_do_not_change_result():
    rows = [F(i * 5) for i in range(30)]; base = ana(rows)
    random.Random(1).shuffle(rows); assert rules(ana(rows)) == rules(base) == {"brute_force"}
    utc = parse_events(f"{HDR}\n2026-10-03T05:30:00Z,auth,h,u,1.1.1.1,login,fail,IN,,0")[0][0]["t"]
    ist = parse_events(f"{HDR}\n2026-10-03T11:00:00+05:30,auth,h,u,1.1.1.1,login,fail,IN,,0")[0][0]["t"]
    naive = parse_events(f"{HDR}\n2026-10-03 11:00:00,auth,h,u,1.1.1.1,login,fail,IN,,0", tz="+05:30")[0][0]["t"]
    assert utc == ist == naive


def test_duplicates_removed_only_when_double_ingested():
    rows = [F(i * 10) for i in range(12)]
    assert any("removed" in w for w in ana(rows * 2)["summary"]["quality"]["warnings"])
    assert not any("removed" in w for w in ana(rows + NOISE)["summary"]["quality"]["warnings"])


def test_all_benign_logs_produce_nothing():
    rnd = random.Random(3); r = ana([F(rnd.randint(0, 3 * 86400), f"u{i % 15}", f"49.1.{i % 15}.1", "fail" if rnd.random() < .05 else "success") for i in range(2000)])
    assert r["summary"]["incidents"] == 0 and r["summary"]["alerts"] == 0


def test_missing_user_and_ip_fields_do_not_crash():
    r = ana([f"{T(i * 5)},auth,vpn01,,,login,fail,,," for i in range(40)])
    assert "brute_force" in rules(r) and any("no username" in w for w in r["summary"]["quality"]["warnings"])


def test_unfamiliar_columns_are_auto_mapped_and_unmappable_ones_ask():
    ev, _ = parse_events("when,who,src,what,result\n" + "\n".join(f"2026-10-03 01:00:{i:02d},bob,1.2.3.4,logon,Failed" for i in range(5)))
    assert ev[0]["user"] == "bob" and ev[0]["ip"] == "1.2.3.4" and ev[0]["outcome"] == "fail"
    with pytest.raises(NeedMapping): parse_events("a,b,c\n1,2,3")
    assert parse_events("a,b,c\nx,y,2026-10-03 01:00:00", mapping={"c": "ts", "a": "user", "b": "ip"})[0][0]["user"] == "x"


def test_malformed_and_large_inputs(client, monkeypatch):
    rnd = random.Random(2); rows = [F(rnd.randint(0, 86400), f"u{i % 300}", f"49.{i % 200}.1.1", "success") if i % 20 else "garbage,,," for i in range(60000)]
    r = client.post("/api/analyze", files={"file": ("big.csv", (HDR + "\n" + "\n".join(rows)).encode())})
    assert r.status_code == 200 and r.json()["summary"]["parse_errors"] >= 2900
    monkeypatch.setattr(main, "MAX_BYTES", 1000)
    assert client.post("/api/analyze", files={"file": ("x.csv", b"a" * 2000)}).status_code == 413
    assert client.post("/api/analyze", files={"file": ("x.bin", bytes(range(256)))}).status_code == 400


def test_api_asks_for_mapping_then_accepts_it(client):
    body = b"a,b,c\nx,y,2026-10-03 01:00:00\n"
    r = client.post("/api/analyze", files={"file": ("m.csv", body)}); assert r.status_code == 422 and r.json()["detail"]["need_mapping"]
    ok = client.post("/api/analyze", files={"file": ("m.csv", body)}, data={"mapping": json.dumps({"c": "ts", "a": "user", "b": "ip"})}); assert ok.status_code == 200


def test_sqlite_search_filters_and_restart_persistence(client):
    client.get("/api/demo")
    assert client.get("/api/search?user=alice&rule=data_exfiltration").json()["total"] == 3
    assert client.get("/api/search?ip=203.0.113.77&start=2026-10-03 01:00&end=2026-10-03 01:05").json()["total"] > 0
    assert client.get("/api/search?start=not-a-date").status_code == 400
    main.STATE.update(res=None, evs=[], runs={}); main.startup()
    assert main.STATE["res"]["summary"]["incidents"] == 2 and client.get("/api/report/1?fmt=md").status_code == 200


def test_adaptive_threshold_rises_in_noisy_environments():
    assert adapt([1, 2, 1, 2] * 10, 8) == 8 and adapt([40, 42, 38, 41] * 10, 8) > 40 and adapt([5], 8) == 8


def test_ai_triage_redacts_for_hosted_models_and_falls_back(client, monkeypatch):
    ev, lab = generate(); res, _ = analyze([_norm(e) for e in ev]); inc = res["incidents"][0]
    assert autotriage.triage(res, inc)["source"] == "local"
    seen = {}
    def fake(system, user, timeout=25):
        seen["p"] = user; return json.dumps({"summary": "address-1 attacked account-1.", "likely_goal": "Steal data", "steps": [{"action": "Disable account-1", "why": "taken over"}], "false_positive_check": "ask owner"}), "m"
    monkeypatch.setattr(autotriage, "call_llm", fake); monkeypatch.setenv("HINDSIGHT_LLM_PROVIDER", "openai-compatible"); monkeypatch.setenv("HINDSIGHT_LLM_API_KEY", "k")
    out = autotriage.triage(res, inc)
    assert "203.0.113.77" not in seen["p"] and "alice" not in seen["p"]
    assert out["source"] == "llm" and "address-1" not in out["summary"] and "account-1" not in out["steps"][0]["action"] and "alice" in out["steps"][0]["action"]


def test_chat_endpoint_is_rate_limited(client, monkeypatch):
    monkeypatch.setenv("HINDSIGHT_RATE_PER_MIN", "3")
    codes = [client.post("/api/chat", json={"question": "hi"}).status_code for _ in range(5)]
    assert codes[:3] == [200] * 3 and codes[3:] == [429] * 2
