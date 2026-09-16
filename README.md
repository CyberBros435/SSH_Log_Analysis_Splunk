# SSH Log Analysis with Splunk

Simulates SSH login activity (successful and failed authentication attempts) on Windows OpenSSH Server, then analyzes the resulting logs in Splunk to detect brute-force-style failed login patterns, with an alert and monitoring dashboard.

## Files
- `report/report.md` — full write-up with screenshots and analysis

## Method
1. Install and enable Windows OpenSSH Server
2. Generate real login activity — failed attempts (wrong password) and successful attempts (correct password, separate local test account)
3. Ingest OpenSSH/Security event logs into Splunk
4. Build clean tables for successful vs failed logins
5. Build an alert on failed login attempts
6. Build a monitoring dashboard (timeline, success/fail ratio, failures by account)

Full report:[report/report.md](SSH_Log_Analysis/report/report.md)
