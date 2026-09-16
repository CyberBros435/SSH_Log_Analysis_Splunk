# Report: SSH Log Analysis with Splunk

## Objective
Set up SSH logging on Windows, generate real successful and failed login activity, analyze it in Splunk, and build detection (alert) and visualization (dashboard) capability around SSH authentication events.

## Theory
- SSH login attempts on Windows are logged via **OpenSSH Server**, which is not installed by default.
- Successful and failed logon attempts also surface in the Windows **Security** event log as EventCode 4624 (successful logon) and EventCode 4625 (failed logon) — the same event codes used for any Windows logon, not SSH-specific, but filterable by process (`sshd.exe`).
- **Why this matters for SOC work**: repeated EventCode 4625 from the same account/source in a short window is the classic signature of a brute-force attack. Distinguishing normal failed logins (typos) from attack patterns (high frequency, many usernames) is a core Tier 1 triage skill.

## Setup — Installing OpenSSH Server

Checked SSH server status — not installed initially:

    sc query sshd

![Confirming sshd service does not exist](ssh1.png)

Checked available Windows capability:

    Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH*'

![OpenSSH Client installed, Server NotPresent](ssh2.png)

Installed and started the server:

    Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
    Start-Service sshd
    Set-Service -Name sshd -StartupType 'Automatic'

![Starting sshd service](ssh3.png)

Verified running:

    Get-Service sshd

![sshd status: Running](ssh4.png)

## Generating Login Activity

### Failed attempts
Attempted SSH login to the primary Windows account, which is a Microsoft account — SSH password authentication against it fails by design (`net user` cannot manage Microsoft account passwords locally either), producing repeated authentication failures:

![Repeated failed SSH attempts against mudas@localhost](ssh5.png)

Attempted to reset the account password locally — blocked, confirming it is a Microsoft-linked account, not a local one:

    net user mudas *

![System error 8646 — account not authoritative for local password change](ssh6.png)

### Creating a local test account for clean success/failure testing
Created a dedicated local account so both outcomes (success and failure) could be generated on demand:

    net user sshtest TestPass123! /add

![sshtest account created; further failed attempts before correct password entered](ssh7.png)

Successful login achieved once the correct password was entered:

![Successful SSH session — sshtest@KALI prompt](ssh8.png)

Confirmed active session with a basic command:

    dir

## Splunk Ingestion & Analysis

### Firewall rule context
While reviewing logs, an incidental firewall rule change event was observed (OpenSSH's inbound firewall rule being deleted/modified), captured as EventCode=4948:

![Firewall exception list change — OpenSSH SSH Server rule deleted](ssh9.png)

Broader OpenSSH-related event volume in Splunk:

    index=* OpenSSH

![75 total OpenSSH-related events found](ssh10.png)

### Failed login events (raw detail)
Initial exploration of failed attempts using keyword search:

    index=* OpenSSH "Failed"
    | table _time, host, Message
    | sort -_time

![19 failed events with full Message field expanded — Failure Reason: Unknown user name or bad password](ssh11.png)

![Expanded raw event showing full Windows logon-failure detail: Account_Name=sshtest, Caller Process=sshd.exe](ssh12.png)

Field extraction attempts with `rex` on the raw text did not initially populate cleanly, so raw event inspection was used to confirm actual field names before building the final clean query:

![Single event capped search confirming raw message structure](ssh13.png)

![Raw _time/host/_raw table across all 75 OpenSSH events](ssh14.png)
![Continued raw table view](ssh15.png)

### Successful login events (raw detail)
Confirmed successful logon raw event structure (EventCode=4624), which provided the correct field names for the clean table query:

![Full successful logon event: Account Name=sshtest, Logon Type=8, Process=sshd.exe](ssh16.png)

### Final clean tables

**Successful logins:**

    index=* OpenSSH EventCode=4624
    | table _time, host, Account_Name, Logon_Type
    | sort -_time

![15 successful login events across mudas and sshtest accounts](ssh17.png)

**Failed logins:**

    index=* OpenSSH EventCode=4625
    | table _time, host, Account_Name, Logon_Type, Failure_Reason
    | sort -_time

![19 failed login events with clean Failure_Reason field populated](ssh18.png)

## Analysis

| Metric | Count | Observation |
|--------|-------|-------------|
| Successful logins (4624) | 15 | Split across `mudas` (blocked/Microsoft account attempts that eventually succeeded via other means) and `sshtest` (local test account) |
| Failed logins (4625) | 19 | All Failure_Reason: "Unknown user name or bad password" — consistent with either wrong password entry or the Microsoft-account authentication mismatch |
| Logon Type | 8 (NetworkCleartext) | Expected for SSH password authentication |

**Finding:** The failed-login volume (19) closely tracks manual testing activity in this session (deliberate wrong-password attempts), not an automated attack — confirmed by the low, human-paced frequency (multiple attempts across ~10 minutes, not dozens per second). This distinction — human-paced failures vs. machine-paced brute force — is the key triage judgment call for this event type in a real environment.

## Alert Configuration

Saved the failed-login query as a scheduled alert:

- **Name**: SSH Failed Login Attempts
- **Trigger condition**: Number of Results > 0
- **Schedule**: Hourly, at 15 minutes past the hour
- **Action**: Add to Triggered Alerts
- **Permissions**: Private, owned by kali

![Alert configuration and status page](ssh19.png)

## Dashboard — SSH Login Monitoring

Built a 3-panel Classic Dashboard:

**Panel 1 — Success vs Failed count:**

    index=* OpenSSH (EventCode=4624 OR EventCode=4625)
    | eval status=if(EventCode=4624, "Success", "Failed")
    | stats count by status

![Success vs Failed count: 19 Failed, 15 Success](ssh20.png)

**Panel 2 — Combined timeline + success/fail chart (dashboard view):**

![SSH Login Monitoring dashboard — timeline panel and success/fail area chart](ssh21.png)

**Panel 3 — Failed attempts by account:**

    index=* OpenSSH EventCode=4625
    | stats count by Account_Name
    | sort -count

![Failed login attempts by account: KALI$ (19), blank (11), sshtest (8)](ssh22.png)

**Full dashboard, all three panels:**

![Complete SSH Login Monitoring dashboard with all panels](ssh23.png)

![Dashboard with account breakdown tooltip showing KALI$ count of 19](ssh24.png)

## MITRE ATT&CK Mapping
| TTP ID | Tactic | Technique |
|--------|--------|-----------|
| T1110.001 | Credential Access | Brute Force: Password Guessing |
| T1021.004 | Lateral Movement | Remote Services: SSH |

## Detection / Defense Notes
- **Baseline first**: this session's 19 failures were manual/testing activity, not an attack — establishing this baseline volume and pacing is necessary before setting a meaningful alert threshold in production (e.g., alert only above N failures per minute, not any single failure).
- **Logon Type 8 (NetworkCleartext)** is expected for password-based SSH — worth confirming this stays consistent; a shift to other logon types on the same service could indicate a different attack vector.
- **Production improvement**: add a `src_ip` field to the failed-login table (not populated in this local-loopback test since source was `localhost`) — real-world SSH brute force detection depends heavily on source IP clustering, which this lab environment could not fully demonstrate due to same-machine testing.
- **Follow-up**: correlate failed SSH logons with subsequent successful logons from the same account within a short window — a classic "eventually succeeded" brute-force indicator.

## Deliverable Status
✅ OpenSSH Server installed and configured
✅ Successful and failed login activity generated
✅ Splunk ingestion confirmed and clean field-extracted tables built
✅ Alert configured (scheduled, hourly, on failed logins)
✅ Dashboard built with timeline, ratio, and per-account breakdown panels