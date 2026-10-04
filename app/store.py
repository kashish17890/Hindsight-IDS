"""SQLite persistence: runs, events (indexed for search) and alert->event links."""
import json, os, sqlite3, threading, time
from contextlib import contextmanager

DB = os.environ.get("HINDSIGHT_DB", "data/hindsight.db")
_lock = threading.Lock()
COLS = "id,ts,source,host,user,ip,event,outcome,country,detail,bytes"


@contextmanager
def db():
    d = os.path.dirname(DB)
    if d: os.makedirs(d, exist_ok=True)
    c = sqlite3.connect(DB, timeout=30); c.row_factory = sqlite3.Row
    c.executescript("""CREATE TABLE IF NOT EXISTS runs(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT,created TEXT,result TEXT);
CREATE TABLE IF NOT EXISTS events(run INT,id INT,t REAL,ts TEXT,source TEXT,host TEXT,user TEXT,ip TEXT,event TEXT,outcome TEXT,country TEXT,detail TEXT,bytes INT,PRIMARY KEY(run,id));
CREATE INDEX IF NOT EXISTS ev_user ON events(run,user);CREATE INDEX IF NOT EXISTS ev_ip ON events(run,ip);CREATE INDEX IF NOT EXISTS ev_t ON events(run,t);
CREATE TABLE IF NOT EXISTS alert_events(run INT,rule TEXT,alert INT,event INT);CREATE INDEX IF NOT EXISTS ae ON alert_events(run,rule,event);""")
    try:
        yield c; c.commit()
    finally:
        c.close()


def save(name, res, evs):
    with _lock, db() as c:
        rid = c.execute("INSERT INTO runs(name,created,result) VALUES(?,?,?)", (name, time.strftime("%Y-%m-%d %H:%M:%S"), "{}")).lastrowid
        res["run"] = rid; res["run_id"] = rid
        c.execute("UPDATE runs SET result=? WHERE id=?", (json.dumps(res), rid))
        c.executemany("INSERT INTO events VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)", [(rid, e["id"], e["t"], e["ts"], e["source"], e["host"], e["user"], e["ip"], e["event"], e["outcome"], e["country"], e["detail"], e["bytes"]) for e in evs])
        c.executemany("INSERT INTO alert_events VALUES(?,?,?,?)", [(rid, a["rule"], a["id"], i) for a in res["alerts"] for i in a["evidence"]])
    return rid


def latest_id():
    with db() as c:
        r = c.execute("SELECT MAX(id) FROM runs").fetchone()[0]
    return r or 0


def result(run=0):
    with db() as c:
        r = c.execute("SELECT result FROM runs WHERE id=?", (run or latest_id(),)).fetchone()
    return json.loads(r[0]) if r else None


def runs():
    with db() as c:
        return [dict(r) for r in c.execute("SELECT id,name,created FROM runs ORDER BY id DESC LIMIT 30")]


def events(run, ids):
    ids = [int(i) for i in ids]
    with db() as c:
        return [dict(r) for r in c.execute(f"SELECT {COLS} FROM events WHERE run=? AND id IN ({','.join('?' * len(ids))}) ORDER BY id", [run] + ids)] if ids else []


def load_events(run):
    with db() as c:
        return [dict(r) for r in c.execute(f"SELECT {COLS} FROM events WHERE run=? ORDER BY id", (run,))]


def search(run, user="", ip="", rule="", q="", start=None, end=None, limit=100, offset=0):
    w, p = ["run=?"], [run]
    if user: w.append("user=?"); p.append(user)
    if ip: w.append("ip=?"); p.append(ip)
    if start is not None: w.append("t>=?"); p.append(start)
    if end is not None: w.append("t<=?"); p.append(end)
    if q: w.append("(detail LIKE ? OR host LIKE ?)"); p += [f"%{q}%"] * 2
    if rule: w.append("id IN (SELECT event FROM alert_events WHERE run=? AND rule=?)"); p += [run, rule]
    where = " AND ".join(w)
    with db() as c:
        total = c.execute(f"SELECT COUNT(*) FROM events WHERE {where}", p).fetchone()[0]
        rows = [dict(r) for r in c.execute(f"SELECT {COLS} FROM events WHERE {where} ORDER BY t,id LIMIT ? OFFSET ?", p + [limit, offset])]
    return dict(total=total, rows=rows)
