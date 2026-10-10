# Live scan examples

Attack log lines you can paste to see **Live scan** react. All IPs are from RFC 5737 documentation ranges.

| File | Paste into | What the Log Monitor should alert on |
|---|---|---|
| `1_ssh_brute_force_to_compromise.txt` | `auth.log` | SSH brute force and password spraying, successful login after brute force, privilege escalation, remote payload download, backdoor account (UID 0) |
| `2_web_attacks.txt` | `nginx_access.log` | SQL injection, path traversal (possibly successful), XSS, command injection, Log4Shell, automated scanner (sqlmap) |
| `3_port_scan_and_c2.txt` | `firewall.log` | Port scan, large outbound transfer to a suspicious port (reverse shell / exfiltration) |

How to use them:

1. In the dashboard, switch on **🔴 Live scan** (leave **Simulation mode** off). It follows the `live_logs/` folder.
2. Paste a file's lines into the **Test it: paste log lines** box in the sidebar and press **Append to log** (pick the matching target file), or append them to `live_logs/<target>` yourself with any editor or `cat >>`.
3. Alerts appear within one check interval. The same attack is alerted only once.

Switch Live scan on **before** pasting: log content that is already in the files when Live scan starts is treated as the baseline and does not alert.
