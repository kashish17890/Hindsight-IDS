"""Synthetic log generator: 7 days of normal traffic, benign decoys, and two labelled attacks."""
import csv, json, random, datetime as dt, argparse, os

FIELDS = ["ts", "source", "host", "user", "ip", "event", "outcome", "country", "detail", "bytes"]
ATTACKER, SCANNER, EXFIL_DST = "203.0.113.77", "198.51.100.200", "192.0.2.99"
START = dt.datetime(2026, 9, 27, tzinfo=dt.timezone.utc)


def generate(seed=7):
    r = random.Random(seed)
    ev = []

    def add(t, source, host, user, ip, event, outcome="", country="IN", detail="", b=0):
        ev.append(dict(ts=t.strftime("%Y-%m-%dT%H:%M:%SZ"), source=source, host=host, user=user,
                       ip=ip, event=event, outcome=outcome, country=country, detail=detail, bytes=b))

    users = [f"user{i:02d}" for i in range(1, 19)] + ["alice", "bob", "carol"]
    home = {u: f"49.{r.randint(30, 200)}.{r.randint(1, 250)}.{r.randint(1, 250)}" for u in users}
    hosts = {u: ["vpn01", r.choice(["app01", "app02", "file01"])] for u in users}
    hosts["alice"] = ["vpn01", "app01"]
    web_ips = [f"34.{r.randint(1, 200)}.{r.randint(1, 250)}.{r.randint(1, 250)}" for _ in range(40)]
    paths = ["/", "/login", "/products", "/api/items", "/about", "/cart", "/static/app.js"]
    cdn = ["151.101.1.10", "104.18.2.2", "13.107.4.50", "142.250.1.1", "17.253.144.10"]

    for d in range(7):
        day = START + dt.timedelta(days=d)
        for u in users:
            for _ in range(r.randint(1, 3)):
                t = day + dt.timedelta(hours=r.randint(9, 17), minutes=r.randint(0, 59), seconds=r.randint(0, 59))
                if r.random() < 0.1:
                    for k in range(r.randint(1, 2)):
                        add(t - dt.timedelta(seconds=20 * (k + 1)), "auth", "vpn01", u, home[u], "login", "fail", "IN")
                for h in hosts[u]:
                    add(t, "auth", h, u, home[u], "login", "success", "IN")
                    t += dt.timedelta(seconds=r.randint(5, 60))
                add(t, "net", hosts[u][-1], u, r.choice(cdn), "net_out", "ok", "", "", r.randint(1000, 4_000_000))
        for _ in range(300):
            t = day + dt.timedelta(seconds=r.randint(0, 86399))
            st = "404" if r.random() < 0.05 else "200"
            add(t, "web", "web01", "", r.choice(web_ips), "http", st, "IN", f"GET {r.choice(paths)}")
        # nightly backup (benign large transfer)
        t = day + dt.timedelta(hours=1, minutes=59)
        add(t, "auth", "file01", "svc_backup", "10.0.0.5", "login", "success", "IN")
        add(t + dt.timedelta(minutes=1), "net", "file01", "svc_backup", "198.51.100.20", "net_out", "ok", "", "nightly backup",
            r.randint(780_000_000, 820_000_000))
        add(t + dt.timedelta(minutes=2), "auth", "app01", "bob", home["bob"], "sudo", "ok", "IN", "sudo apt update")

    D = lambda *a: dt.datetime(*a, tzinfo=dt.timezone.utc)
    # --- benign decoys ---
    for k in range(4):  # carol mistypes 4 times then succeeds (below brute-force threshold)
        add(D(2026, 10, 2, 11, 0, 5 * k), "auth", "vpn01", "carol", home["carol"], "login", "fail", "IN")
    add(D(2026, 10, 2, 11, 1), "auth", "vpn01", "carol", home["carol"], "login", "success", "IN")
    add(D(2026, 10, 2, 2, 0), "auth", "vpn01", "bob", "198.51.100.140", "login", "success", "US")  # genuine travel
    add(D(2026, 10, 2, 3, 10), "auth", "vpn01", "user10", home["user10"], "login", "success", "IN")  # odd hour

    # --- attack 1: multi-stage intrusion (night of 3 Oct) ---
    add(D(2026, 10, 2, 23, 55), "auth", "vpn01", "alice", home["alice"], "login", "success", "IN")
    t = D(2026, 10, 3, 1, 0)
    for i in range(70):
        add(t + dt.timedelta(seconds=2 * i), "web", "web01", "", ATTACKER, "http",
            r.choice(["404", "404", "403"]), "RO", "GET " + r.choice(["/admin", "/.git/config", "/wp-login.php", "/backup.zip", "/.env", "/phpmyadmin"]))
    for i, p in enumerate(["/search?q=' OR 1=1--", "/item?id=1 UNION SELECT user,pass FROM users", "/view?f=../../etc/passwd", "/search?q=<script>alert(1)</script>"]):
        add(t + dt.timedelta(seconds=150 + i), "web", "web01", "", ATTACKER, "http", "500", "RO", "GET " + p)
    t = D(2026, 10, 3, 1, 10)
    for i, u in enumerate(r.sample(users, 8)):
        for k in range(2):
            add(t + dt.timedelta(seconds=20 * i + 5 * k), "auth", "vpn01", u, ATTACKER, "login", "fail", "RO")
    t = D(2026, 10, 3, 1, 14)
    for i in range(18):
        add(t + dt.timedelta(seconds=8 * i), "auth", "vpn01", "alice", ATTACKER, "login", "fail", "RO")
    add(D(2026, 10, 3, 1, 17), "auth", "vpn01", "alice", ATTACKER, "login", "success", "RO")
    add(D(2026, 10, 3, 1, 19), "auth", "app01", "alice", "10.0.4.21", "role_change", "ok", "IN", "alice added to group admins")
    for i, h in enumerate(["db01", "file01", "dc01", "bastion"]):
        add(D(2026, 10, 3, 1, 22 + i), "auth", h, "alice", "10.0.4.21", "login", "success", "IN")
    for i, b in enumerate([150_000_000, 120_000_000, 110_000_000]):
        add(D(2026, 10, 3, 1, 30 + 4 * i), "net", "db01", "alice", EXFIL_DST, "net_out", "ok", "", "", b)
    add(D(2026, 10, 3, 1, 44), "auth", "app01", "alice", "10.0.4.21", "log_cleared", "ok", "IN", "auth.log truncated")

    # --- attack 2: noisy scanner (recon + injection only) ---
    t = D(2026, 10, 2, 15, 0)
    for i in range(120):
        add(t + dt.timedelta(seconds=2 * i), "web", "web01", "", SCANNER, "http", "404", "CN", "GET /" + r.choice(["a.php", "x", "cgi-bin/test", "old", "db.sql"]))
    for i in range(5):
        add(t + dt.timedelta(seconds=250 + i), "web", "web01", "", SCANNER, "http", "500", "CN", "GET /q?id=1' OR '1'='1")

    labels = {"malicious_ips": [ATTACKER, SCANNER, EXFIL_DST], "malicious_users": ["alice"]}
    ev.sort(key=lambda e: e["ts"])
    return ev, labels


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="logs")
    ap.add_argument("--seed", type=int, default=7)
    a = ap.parse_args()
    events, labels = generate(a.seed)
    os.makedirs(a.out, exist_ok=True)
    with open(f"{a.out}/sample_logs.csv", "w", newline="") as f:
        w = csv.DictWriter(f, FIELDS); w.writeheader(); w.writerows(events)
    json.dump(labels, open(f"{a.out}/labels.json", "w"), indent=2)
    print(f"wrote {len(events)} events to {a.out}/sample_logs.csv")
