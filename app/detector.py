"""Detection engine: parse -> rules -> alerts -> incidents (entity-graph correlation) -> kill-chain story."""
import csv, io, json, math, re, time, datetime as dt
from collections import defaultdict

SEV_W = {"low": 5, "medium": 20, "high": 40, "critical": 60}
SEV_ORDER = ["low", "medium", "high", "critical"]
STAGES = ["Reconnaissance", "Credential Access", "Initial Access", "Privilege Escalation",
          "Defense Evasion", "Lateral Movement", "Exfiltration"]
RULES = {  # id: (title, severity, tactic, MITRE technique)
    "brute_force": ("Brute-force login burst", "high", "Credential Access", "T1110.001"),
    "password_spray": ("Password spraying", "high", "Credential Access", "T1110.003"),
    "compromise_after_failures": ("Login succeeded after failures", "critical", "Initial Access", "T1078"),
    "impossible_travel": ("Impossible travel", "high", "Initial Access", "T1078"),
    "priv_escalation": ("Privilege escalation", "medium", "Privilege Escalation", "T1068"),
    "lateral_movement": ("Lateral movement to new hosts", "high", "Lateral Movement", "T1021"),
    "data_exfiltration": ("Large outbound transfer", "critical", "Exfiltration", "T1041"),
    "web_scan": ("Web scanning / forced browsing", "medium", "Reconnaissance", "T1595"),
    "web_injection": ("Injection / traversal payloads", "high", "Initial Access", "T1190"),
    "log_tampering": ("Log tampering", "high", "Defense Evasion", "T1070"),
    "off_hours": ("First-ever off-hours login", "low", "Initial Access", "T1078"),
    "low_slow_bruteforce": ("Low-and-slow password guessing", "high", "Credential Access", "T1110.001"),
    "distributed_attack": ("Distributed attack on one account", "high", "Credential Access", "T1110.004"),
}
PAYLOAD = re.compile(r"(?i)(union\s+select|or\s+1=1|'\s*or\s*'|\.\./|<script|/etc/passwd|sleep\()")
SSHD = re.compile(r"(\w{3}\s+\d+\s+[\d:]+)\s+(\S+)\s+sshd\[\d+\]:\s+(Failed|Accepted) password for (?:invalid user )?(\S+) from (\S+)")


# ---------------------------------------------------------------- parsing
ALIAS = {"timestamp": "ts", "time": "ts", "@timestamp": "ts", "datetime": "ts", "date": "ts", "src_ip": "ip", "source_ip": "ip",
         "client_ip": "ip", "remote_addr": "ip", "clientip": "ip", "username": "user", "account": "user", "user_name": "user",
         "action": "event", "type": "event", "status": "outcome", "result": "outcome", "message": "detail", "msg": "detail",
         "hostname": "host", "server": "host", "bytes_out": "bytes", "size": "bytes", "geo": "country"}
OUTC = {"failed": "fail", "failure": "fail", "denied": "fail", "invalid": "fail", "succeeded": "success", "accepted": "success", "successful": "success"}
EVT = {"logon": "login", "signin": "login", "sign-in": "login", "authentication": "login", "auth": "login", "ssh": "login"}
APACHE = re.compile(r'^(\S+) \S+ (\S+) \[([^\]]+)\] "(\w+) (\S+)[^"]*" (\d{3}) (\d+|-)')
FMTS = ("%Y-%m-%d %H:%M:%S", "%d/%m/%Y %H:%M:%S", "%m/%d/%Y %H:%M:%S", "%d/%b/%Y:%H:%M:%S %z")


class NeedMapping(Exception):
    def __init__(self, headers, sample, guess):
        self.info = dict(need_mapping=True, headers=[str(h) for h in headers], sample=sample, guess=guess)
        super().__init__("column mapping needed")


FIELDS = ["ts", "source", "host", "user", "ip", "event", "outcome", "country", "detail", "bytes"]
KEYWORDS = [("ts", ("time", "date", "stamp", "when")), ("ip", ("ip", "addr", "src", "client", "remote")),
            ("user", ("user", "account", "login", "who", "principal")), ("host", ("host", "machine", "device", "server", "node")),
            ("outcome", ("status", "result", "outcome", "success")), ("country", ("country", "geo")),
            ("bytes", ("byte", "size", "length")), ("detail", ("msg", "message", "info", "desc", "url", "path", "request")),
            ("event", ("event", "action", "type", "what"))]
INVALID = re.compile(r"(\w{3}\s+\d+\s+[\d:]+)\s+(\S+)\s+sshd\[\d+\]:\s+Invalid user (\S+) from (\S+)")


def guess_mapping(headers):
    g, used = {}, set()
    for h in headers:
        l = str(h).strip().lower(); f = ALIAS.get(l, l if l in FIELDS else None)
        if not f:
            toks = re.split(r"[^a-z]+", l)
            f = next((k for k, ws in KEYWORDS if any(t == w or (len(w) > 3 and t.startswith(w)) for t in toks for w in ws)), None)
        if f and f not in used: g[h] = f; used.add(f)
    return g


def tz_offset(s):
    m = re.search(r"([+-])\s*(\d{1,2}):?(\d{2})?", str(s or ""))
    return 0.0 if not m else (1 if m.group(1) == "+" else -1) * (int(m.group(2)) * 3600 + int(m.group(3) or 0) * 60)


def _epoch(ts, off=0.0):
    """Returns (epoch_seconds, was_naive). Naive times are read as UTC shifted by `off` (log zone, seconds east of UTC)."""
    ts = str(ts).strip()
    if ts.replace(".", "", 1).isdigit():
        v = float(ts); return (v / 1000 if v > 1e12 else v), False
    try:
        d = dt.datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        for f in FMTS:
            try: d = dt.datetime.strptime(ts, f); break
            except ValueError: pass
        else: raise ValueError("unknown time format: " + ts)
    if d.tzinfo: return d.timestamp(), False
    return d.replace(tzinfo=dt.timezone.utc).timestamp() - off, True


def _norm(d, off=0.0, mapping=None):
    m = mapping or {}
    d = {m.get(k, ALIAS.get(str(k).strip().lower(), str(k).strip().lower())): (v.isoformat() if hasattr(v, "isoformat") else v) for k, v in d.items() if k is not None}
    e = {k: str(d.get(k, "") or "").strip() for k in ["ts", "source", "host", "user", "ip", "event", "outcome", "country", "detail"]}
    try: e["bytes"] = int(float(d.get("bytes") or 0))
    except ValueError: e["bytes"] = 0
    e["t"], e["naive"] = _epoch(e["ts"], off)
    e["ts"] = dt.datetime.fromtimestamp(e["t"], dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    e["outcome"] = OUTC.get(e["outcome"].lower(), e["outcome"])
    e["event"] = EVT.get(e["event"].lower(), e["event"]) or ("login" if e["outcome"] in ("fail", "success") else "")
    if not e["source"]:
        e["source"] = "web" if e["event"] == "http" or e["detail"][:4] in ("GET ", "POST") else "net" if e["bytes"] and e["event"] != "login" else "auth"
    return e


def _rows_to_events(rows, off=0.0, mapping=None):
    out, errs = [], 0
    for d in rows:
        try: out.append(_norm(d, off, mapping))
        except Exception: errs += 1
    return out, errs


def _resolve(rows, mapping):
    if mapping: return mapping
    keys = list(rows[0].keys())
    g = guess_mapping(keys)
    if "ts" not in g.values():
        raise NeedMapping(keys, [{str(k): str(v)[:60] for k, v in r.items()} for r in rows[:3]], g)
    return g


def _syslog_year(m):
    t = dt.datetime.strptime(f"{dt.datetime.now().year} {m}", "%Y %b %d %H:%M:%S").replace(tzinfo=dt.timezone.utc)
    return t.replace(year=t.year - 1) if t.timestamp() > time.time() + 86400 else t


def parse_events(text, tz="", mapping=None):
    """CSV/TSV (any column names - auto-mapped), JSON lines/array, Apache/nginx access log, sshd syslog.
    Raises NeedMapping if a table has no recognisable time column."""
    text = text.strip().lstrip("\ufeff")
    if not text: return [], 0
    off, rows, errs, first, canon = tz_offset(tz), [], 0, text.split("\n", 1)[0], False
    if text.startswith("["):
        try: rows = json.loads(text)
        except Exception: errs += 1
    elif text.startswith("{"):
        for ln in text.splitlines():
            try: rows.append(json.loads(ln))
            except Exception: errs += 1
    elif len(re.split(r"[,\t;]", first)) > 2 and not SSHD.search(first) and not APACHE.match(first):
        delim = "\t" if first.count("\t") >= first.count(",") and "\t" in first else (";" if first.count(";") > first.count(",") else ",")
        rows = list(csv.DictReader(io.StringIO(text), delimiter=delim))
    else:
        canon = True
        for ln in text.splitlines():
            m, a, iv = SSHD.search(ln), APACHE.match(ln), INVALID.search(ln)
            if m:
                rows.append(dict(ts=_syslog_year(m.group(1)).isoformat(), source="auth", host=m.group(2), user=m.group(4), ip=m.group(5),
                                 event="login", outcome="fail" if m.group(3) == "Failed" else "success"))
            elif iv:
                rows.append(dict(ts=_syslog_year(iv.group(1)).isoformat(), source="auth", host=iv.group(2), user=iv.group(3), ip=iv.group(4), event="login", outcome="fail"))
            elif a:
                rows.append(dict(ts=a.group(3), source="web", host="web", user="", ip=a.group(1), event="http", outcome=a.group(6), detail=f"{a.group(4)} {a.group(5)}"))
            elif ln.strip(): errs += 1
    rows = [r for r in rows if isinstance(r, dict)]
    if rows and not canon: mapping = _resolve(rows, mapping)
    ev, e2 = _rows_to_events(rows, off, None if canon else mapping)
    return ev, errs + e2


def parse_file(name, data, tz="", mapping=None):
    """Upload entry point: .xlsx/.xlsm, .json/.jsonl, .csv/.tsv, .txt/.log (auto-detected)."""
    ext = name.lower().rsplit(".", 1)[-1] if "." in name else ""
    if ext in ("xlsx", "xlsm"):
        import openpyxl
        ws = openpyxl.load_workbook(io.BytesIO(data), read_only=True, data_only=True).worksheets[0]
        it = ws.iter_rows(values_only=True)
        head = [str(h or "") for h in next(it, [])]
        rows = [dict(zip(head, r)) for r in it if any(c is not None for c in r)]
        if not rows: return [], 0
        return _rows_to_events(rows, tz_offset(tz), _resolve(rows, mapping))
    if ext == "xls":
        raise ValueError("Old .xls files are not supported - save the sheet as .xlsx or .csv and upload again.")
    return parse_events(data.decode("utf-8", errors="replace"), tz, mapping)


PLAIN = {  # rule: (what it means in plain English, what to do)
    "brute_force": ("Someone kept guessing passwords on accounts at machine speed.", "Lock or rate-limit the targeted accounts and block the source address."),
    "password_spray": ("One address tried a few common passwords against many different accounts.", "Force password resets on the targeted accounts and turn on multi-factor sign-in."),
    "compromise_after_failures": ("After many failed tries, a login finally worked - the account was probably taken over.", "Disable the account now, reset its password and sign out all its sessions."),
    "impossible_travel": ("The same account signed in from two countries too close together for a real person to travel.", "Ask the owner to confirm; if not them, lock the account."),
    "priv_escalation": ("An account was given extra powers (admin rights).", "Check who approved it and remove the rights if unexpected."),
    "lateral_movement": ("One account suddenly reached several machines it had never used before.", "Isolate the machines it touched and review what was accessed."),
    "data_exfiltration": ("An unusually large amount of data left the network in one go.", "Block the destination, work out which data left, and start your breach process."),
    "web_scan": ("A visitor tried hundreds of hidden or non-existent pages, looking for weak spots.", "Block the address and make sure admin and backup pages are not exposed."),
    "web_injection": ("A visitor sent code-like text to the website to try to trick it.", "Check the targeted pages for weaknesses and keep the firewall rules updated."),
    "log_tampering": ("Someone erased or cut the activity records, usually to hide what they did.", "Preserve backups of the logs and treat this machine as compromised."),
    "off_hours": ("An account signed in at an hour it has never used before.", "Low risk alone - confirm with the owner if other warnings exist."),
    "low_slow_bruteforce": ("Someone is guessing passwords very slowly over hours to avoid being noticed.", "Block the address and add a daily (not just per-minute) failed-login limit."),
    "distributed_attack": ("Many different addresses each tried one account a few times - a coordinated attack.", "Force a password reset for that account and require multi-factor sign-in."),
}


def compute_stats(evs, alerts):
    from collections import Counter as C
    return dict(severity=dict(C(a["severity"] for a in alerts)), tactic=dict(C(a["tactic"] for a in alerts)),
                countries=C(e["country"] for e in evs if e["country"]).most_common(8),
                failed_ips=C(e["ip"] for e in evs if e["source"] == "auth" and e["event"] == "login" and e["outcome"] == "fail" and e["ip"]).most_common(8),
                auth=dict(C(e["outcome"] for e in evs if e["source"] == "auth" and e["event"] == "login" and e["outcome"] in ("fail", "success"))),
                sources=dict(C(e["source"] for e in evs)), bytes_out=sum(e["bytes"] for e in evs if e["source"] == "net"))


# ---------------------------------------------------------------- helpers
def private(ip): return ip.startswith(("10.", "192.168.", "172.16.", "127."))


def maxwin(es, span):
    best, j = 0, 0
    for i in range(len(es)):
        while es[i]["t"] - es[j]["t"] > span: j += 1
        best = max(best, i - j + 1)
    return best


def adapt(vals, floor, k=6, min_n=20):
    """Adaptive threshold: median + k*MAD of the observed population, never below `floor`.
    Robust to the attackers themselves (percentiles drift upward when attacks are common)."""
    if len(vals) < min_n: return floor
    v = sorted(vals); med = v[len(v) // 2]; mad = sorted(abs(x - med) for x in v)[len(v) // 2]
    return max(floor, math.ceil(med + k * max(mad, 1)))


def bursts(evs, span, n, distinct=None):
    out, i = [], 0
    while i < len(evs):
        j = i
        while j < len(evs) and evs[j]["t"] - evs[i]["t"] <= span: j += 1
        win = evs[i:j]
        if (len({distinct(e) for e in win}) if distinct else len(win)) >= n:
            k = j
            while k < len(evs) and evs[k]["t"] - evs[k - 1]["t"] <= span: k += 1
            out.append(evs[i:k]); i = k
        else:
            i += 1
    return out


def clock(t): return dt.datetime.fromtimestamp(t, dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


# ---------------------------------------------------------------- analysis
def analyze(events, labels=None):
    events = list(events); n_in = len(events); seen_k, uniq = set(), []
    for e in events:
        k = (e["t"], e["source"], e["host"], e["user"], e["ip"], e["event"], e["outcome"], e["detail"], e["bytes"])
        if k not in seen_k: seen_k.add(k); uniq.append(e)
    dups = n_in - len(uniq); dedup = bool(n_in and dups / n_in >= 0.3)  # many exact dupes = double ingestion
    evs = sorted(uniq if dedup else events, key=lambda e: e["t"])
    for i, e in enumerate(evs): e["id"] = i
    if not evs:
        return dict(summary=dict(events=0, alerts=0, incidents=0, suppressed=0, span="-"), alerts=[], incidents=[], entities=[], suppressed=[], hourly=[], eval=None), evs
    t0, span = evs[0]["t"], evs[-1]["t"] - evs[0]["t"]
    warm = t0 + min(86400, span * 0.25)  # learning period for baselines
    au = [e for e in evs if e["source"] == "auth" and e["event"] == "login"]
    mu = round(100 * sum(1 for e in au if not e["user"]) / len(au)) if au else 0
    mi = round(100 * sum(1 for e in au if not e["ip"]) / len(au)) if au else 0
    naive, fut, W = sum(1 for e in evs if e.get("naive")), sum(1 for e in evs if e["t"] > time.time() + 86400), []
    if dups: W.append(f"{dups} exact duplicate lines " + ("were removed (looks like the file was ingested twice)." if dedup else "were kept (they may be genuine repeated events)."))
    if naive > len(evs) / 2: W.append("Timestamps had no time zone, so UTC was assumed. If your logs use local time, set the time zone when uploading.")
    if mu > 20: W.append(f"{mu}% of sign-in lines have no username, so account-based rules are less reliable.")
    if mi > 20: W.append(f"{mi}% of sign-in lines have no IP address, so address-based rules fall back to usernames.")
    if fut: W.append(f"{fut} events are dated in the future - check the time zone or clock.")
    if span < 3600: W.append("The data covers under an hour. Baseline rules (new machines, unusual hours) need at least a day of history and were largely skipped.")
    q = dict(events_in=n_in, duplicates=dups, missing_user_pct=mu, missing_ip_pct=mi, naive_ts=naive, future=fut, warnings=W)
    alerts, suppressed = [], []

    def alert(rule, es, why, ip="", user="", host="", t=None):
        title, sev, tactic, mitre = RULES[rule]
        ip = "" if ip.startswith("?") else ip
        tt = t if t is not None else es[0]["t"]
        alerts.append(dict(id=len(alerts), rule=rule, title=title, severity=sev, tactic=tactic, mitre=mitre,
                           ts=clock(tt), t=tt, plain=PLAIN[rule][0], action=PLAIN[rule][1], ip=ip, user=user, host=host, why=why,
                           evidence=[e["id"] for e in es][:300], n_evidence=len(es)))

    def skip(rule, why, es):
        suppressed.append(dict(rule=rule, reason=why, ts=clock(es[0]["t"]), evidence=[e["id"] for e in es][:50]))

    auth = [e for e in evs if e["source"] == "auth" and e["event"] == "login"]
    fails, succ = [e for e in auth if e["outcome"] == "fail"], [e for e in auth if e["outcome"] == "success"]
    fkey = lambda e: e["ip"] or ("?" + e["user"])
    fails_ip = defaultdict(list)
    for e in fails: fails_ip[fkey(e)].append(e)

    thr = {}
    thr["brute_force_per_5min"] = thr_b = adapt([maxwin(v, 300) for v in fails_ip.values()], 8)
    for ip, fl in fails_ip.items():
        for b in bursts(fl, 300, thr_b):
            alert("brute_force", b, f"{ip} failed {len(b)} logins in {int(b[-1]['t'] - b[0]['t'])}s (targets: {', '.join(sorted({e['user'] for e in b})[:4])}).", ip=ip)
        for b in bursts(fl, 600, 5, distinct=lambda e: e["user"]):
            us = {e["user"] for e in b}
            alert("password_spray", b, f"{ip} tried {len(us)} different accounts within {int(b[-1]['t'] - b[0]['t'])}s.", ip=ip)

    for ip, fl in fails_ip.items():  # low-and-slow: many failures spread over hours, below burst thresholds
        if len(fl) < 15 or any(a["rule"] == "brute_force" and (a["ip"] == ip or not a["ip"]) for a in alerts): continue
        j = 0
        for i in range(len(fl)):
            while fl[i]["t"] - fl[j]["t"] > 86400: j += 1
            w = fl[j:i + 1]
            if len(w) >= 15 and len({int(e["t"] // 3600) for e in w}) >= 4:
                alert("low_slow_bruteforce", w, f"{ip} made {len(w)} failed logins spread over {int((w[-1]['t'] - w[0]['t']) / 3600)}h - slow enough to dodge burst alarms.", ip=ip); break
    by_user = defaultdict(list)
    for e in fails:
        if e["user"]: by_user[e["user"]].append(e)
    for u, fl in by_user.items():  # distributed: many addresses, each trying only a little
        for b in bursts(fl, 3600, 5, distinct=lambda e: e["ip"]):
            alert("distributed_attack", b, f"{u} was attacked from {len({e['ip'] for e in b})} different addresses within {int(b[-1]['t'] - b[0]['t'])}s, each trying only a few times.", user=u)

    seen_pair = set()
    for e in succ:
        prior = [f for f in fails_ip.get(fkey(e), []) if 0 <= e["t"] - f["t"] <= 900]
        if len(prior) >= 5 and (e["ip"], e["user"]) not in seen_pair:
            seen_pair.add((e["ip"], e["user"]))
            alert("compromise_after_failures", prior[-10:] + [e], f"{e['user']} logged in from {e['ip']} ({e['country']}) right after {len(prior)} failed attempts from the same address.", ip=e["ip"], user=e["user"], host=e["host"], t=e["t"])
        elif 3 <= len(prior) < 5 and e["user"] == prior[-1]["user"] and (e["user"], prior[-1]["id"]) not in seen_pair:
            seen_pair.add((e["user"], prior[-1]["id"]))
            skip("compromise_after_failures", f"{e['user']}: {len(prior)} failures then success - below threshold, looks like typos.", prior + [e])

    last = {}
    for e in succ:
        p = last.get(e["user"])
        if p and p["country"] and e["country"] and p["country"] != e["country"]:
            gap = e["t"] - p["t"]
            if gap < 7200:
                alert("impossible_travel", [p, e], f"{e['user']} logged in from {p['country']} then {e['country']} {int(gap / 60)} min later.", ip=e["ip"], user=e["user"], t=e["t"])
            elif gap < 86400:
                skip("impossible_travel", f"{e['user']}: {p['country']} -> {e['country']} with {gap / 3600:.0f}h gap - plausible travel.", [p, e])
        last[e["user"]] = e

    for e in evs:
        if e["event"] in ("role_change", "priv_escalation"):
            alert("priv_escalation", [e], f"{e['user']}: {e['detail'] or e['event']} on {e['host']}.", user=e["user"], host=e["host"])
        elif e["event"] == "log_cleared":
            alert("log_tampering", [e], f"{e['user']} cleared logs on {e['host']} ({e['detail']}).", user=e["user"], host=e["host"])

    seen_h, recent, last_alert, hrs = defaultdict(set), defaultdict(list), {}, defaultdict(set)
    for e in succ:
        u = e["user"]
        if e["host"] not in seen_h[u]:
            seen_h[u].add(e["host"])
            if e["t"] >= warm:
                recent[u] = [x for x in recent[u] if e["t"] - x["t"] <= 900] + [e]
                if len({x["host"] for x in recent[u]}) >= 3 and e["t"] - last_alert.get(u, 0) > 900:
                    last_alert[u] = e["t"]
                    alert("lateral_movement", recent[u], f"{u} authenticated to {len(recent[u])} hosts never seen before ({', '.join(x['host'] for x in recent[u])}) within {int(e['t'] - recent[u][0]['t'])}s.", user=u, host=e["host"], t=e["t"])
        hr = dt.datetime.fromtimestamp(e["t"], dt.timezone.utc).hour
        if hr < 5 and e["t"] >= warm and not any(h < 5 for h in hrs[u]):
            alert("off_hours", [e], f"{u} logged in at {hr:02d}:xx UTC for the first time ever outside normal hours.", ip=e["ip"], user=u)
        hrs[u].add(hr)

    thr["exfil_bytes"] = thr_x = adapt([e["bytes"] for e in evs if e["source"] == "net" and e["bytes"] > 0], 50_000_000, k=10)
    grp = defaultdict(list)
    for e in evs:
        if e["source"] == "net" and e["bytes"] > 0: grp[(e["user"], e["ip"])].append(e)
    for (u, ip), es in grp.items():
        clusters, cur = [], [es[0]]
        for e in es[1:]:
            if e["t"] - cur[-1]["t"] <= 900: cur.append(e)
            else: clusters.append(cur); cur = [e]
        clusters.append(cur)
        big = [c for c in clusters if sum(x["bytes"] for x in c) >= thr_x]
        days = {clock(c[0]["t"])[:10] for c in big}
        if len(days) >= 3:
            skip("data_exfiltration", f"{u} -> {ip}: large transfer recurs on {len(days)} different days - scheduled job.", big[0])
        else:
            for c in big:
                mb = sum(x["bytes"] for x in c) / 1e6
                alert("data_exfiltration", c, f"{u} sent {mb:.0f} MB from {c[0]['host']} to {ip} in {len(c)} transfers.", ip=ip, user=u, host=c[0]["host"])

    web_ip = defaultdict(list)
    for e in evs:
        if e["source"] == "web": web_ip[e["ip"]].append(e)
    thr["web_errors_per_5min"] = thr_w = adapt([maxwin([e for e in es if e["outcome"] in ("403", "404")], 300) for es in web_ip.values()], 20)
    for ip, es in web_ip.items():
        for b in bursts([e for e in es if e["outcome"] in ("403", "404")], 300, thr_w):
            alert("web_scan", b, f"{ip} generated {len(b)} 403/404 responses in {int(b[-1]['t'] - b[0]['t'])}s.", ip=ip)
        for b in bursts([e for e in es if PAYLOAD.search(e["detail"])], 600, 3):
            alert("web_injection", b, f"{ip} sent {len(b)} requests with injection/traversal/XSS payloads.", ip=ip)

    alerts.sort(key=lambda a: a["t"])
    for i, a in enumerate(alerts): a["id"] = i

    # ---- correlation: union-find over users and external IPs
    parent = {}
    def find(x):
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]; x = parent[x]
        return x
    def ents(a):
        return ([f"user:{a['user']}"] if a["user"] else []) + ([f"ip:{a['ip']}"] if a["ip"] and not private(a["ip"]) else [])
    key = {}
    for a in alerts:
        es = ents(a) or [f"alert:{a['id']}"]
        for x in es[1:]: parent[find(x)] = find(es[0])
        find(es[0]); key[a["id"]] = es[0]
    comps = defaultdict(list)
    for a in alerts: comps[find(key[a["id"]])].append(a)

    incidents = []
    for al in comps.values():
        score = sum(SEV_W[a["severity"]] for a in al)
        if score < 50: continue
        stages = [s for s in STAGES if any(a["tactic"] == s for a in al)]
        conf = min(0.98, 0.30 + 0.12 * len(stages) + 0.03 * len(al))
        sev = max((a["severity"] for a in al), key=SEV_ORDER.index)
        ips = sorted({a["ip"] for a in al if a["ip"] and not private(a["ip"])})
        users = sorted({a["user"] for a in al if a["user"]})
        incidents.append(dict(
            severity=sev, score=score, confidence=round(conf, 2), stages=stages, ips=ips, users=users,
            start=al[0]["ts"], end=al[-1]["ts"], alerts=[a["id"] for a in al],
            narrative=" ".join(f"[{a['ts'][11:]}] {a['why']}" for a in al),
            factors=[f"{len(stages)} of 7 kill-chain stages observed ({', '.join(stages)})",
                     f"{len(al)} correlated alerts from {len(ips)} external address(es) and {len(users)} account(s)",
                     f"peak severity: {sev}"],
            title=f"{sev.title()} incident: {next((a['ip'] for a in al if a['ip'] and not private(a['ip'])), 'internal')}" + (f" -> {users[0]}" if users else "")))
    incidents.sort(key=lambda i: (-SEV_ORDER.index(i["severity"]), -i["score"]))
    for inc in incidents:
        al = [alerts[i] for i in inc["alerts"]]
        seen = list(dict.fromkeys(a["rule"] for a in al))
        first_ip = next((a["ip"] for a in al if a["ip"] and not private(a["ip"])), "")
        who = (first_ip or "an internal source") + (f" and the account '{inc['users'][0]}'" if inc["users"] else "")
        inc["plain"] = f"Activity linked to {who} looks like a deliberate attack, not normal use. In order: " + " ".join(PLAIN[r][0] for r in seen)
        inc["actions"] = [PLAIN[r][1] for r in seen[::-1]] + ["Keep the evidence below - export the report for your records."]
    amap = {}
    for i, inc in enumerate(incidents):
        inc["id"] = i + 1
        for aid in inc["alerts"]: amap[aid] = inc["id"]
    for a in alerts: a["incident"] = amap.get(a["id"])

    risk = defaultdict(int); cnt = defaultdict(int)
    for a in alerts:
        for k in ([("user", a["user"])] if a["user"] else []) + ([("ip", a["ip"])] if a["ip"] and not private(a["ip"]) else []):
            risk[k] += SEV_W[a["severity"]]; cnt[k] += 1
    entities = [dict(type=k[0], name=k[1], risk=min(100, v), alerts=cnt[k]) for k, v in sorted(risk.items(), key=lambda kv: -kv[1])]

    hourly = defaultdict(lambda: [0, 0])
    for e in evs: hourly[clock(e["t"])[:13]][0] += 1
    for a in alerts: hourly[a["ts"][:13]][1] += 1
    hourly = [dict(h=h, events=v[0], alerts=v[1]) for h, v in sorted(hourly.items())]

    ev_report = None
    if labels:
        truth = {f"ip:{x}" for x in labels["malicious_ips"]} | {f"user:{x}" for x in labels["malicious_users"]}
        pred = {f"ip:{x}" for i in incidents for x in i["ips"]} | {f"user:{x}" for i in incidents for x in i["users"]}
        tp = len(truth & pred); p = tp / len(pred) if pred else 0; r_ = tp / len(truth) if truth else 0
        ev_report = dict(precision=round(p, 3), recall=round(r_, 3), f1=round(2 * p * r_ / (p + r_), 3) if p + r_ else 0,
                         missed=sorted(truth - pred), false_positives=sorted(pred - truth), truth=len(truth))
    res = dict(summary=dict(events=len(evs), alerts=len(alerts), incidents=len(incidents), suppressed=len(suppressed), quality=q,
                            span=f"{clock(t0)} to {clock(evs[-1]['t'])}"),
               alerts=alerts, incidents=incidents, entities=entities[:25], suppressed=suppressed, hourly=hourly, eval=ev_report, stats=compute_stats(evs, alerts), thresholds=thr)
    return res, evs


def report_md(res, inc, evs):
    L = [f"# Incident #{inc['id']} - {inc['title']}", "", f"**Window:** {inc['start']} to {inc['end']}  ",
         f"**Confidence:** {int(inc['confidence'] * 100)}%  **Score:** {inc['score']}", "",
         "## Why we believe this", *[f"- {f}" for f in inc["factors"]], "", "## Attack story", ""]
    for aid in inc["alerts"]:
        a = res["alerts"][aid]
        L.append(f"- **{a['ts']}** [{a['severity']}] {a['title']} ({a['tactic']}, MITRE {a['mitre']}): {a['why']}")
    L += ["", "## Evidence (raw log lines)", ""]
    for aid in inc["alerts"]:
        a = res["alerts"][aid]; L.append(f"### {a['title']}")
        for i in a["evidence"][:8]:
            e = evs[i]; L.append(f"- `{e['ts']} {e['source']} {e['host']} user={e['user']} ip={e['ip']} {e['event']} {e['outcome']} {e['detail']} {e['bytes'] or ''}`")
    return "\n".join(L)
