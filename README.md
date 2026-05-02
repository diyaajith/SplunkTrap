#  SplunkTrap

**A Splunk-based Detection Engineering Lab** simulating multi-vector Windows attacks including Active Directory abuse, brute force credential attacks, privilege escalation, and ransomware-like file access behaviour — with custom correlation searches, saved alerts, and documented SPL detection logic.

> Built on Splunk Enterprise 10.2.2 | Windows Security Event Logs | MITRE ATT&CK Mapped

---

##  Lab Objectives

- Ingest and parse Windows Security Event Logs using Splunk's `WinEventLog:Security` sourcetype
- Write SPL correlation searches to detect real-world attack patterns
- Build and tune saved alerts with noise-reduction techniques (service account filtering, logon type classification)
- Map all detections to MITRE ATT&CK techniques
- Document detection logic for reproducibility and portfolio use

---

##  Detections Built

### 1. Brute Force Followed by Successful Login
**MITRE:** T1110.001 – Brute Force: Password Guessing | T1078 – Valid Accounts

Detects when an account suffers multiple failed logon attempts (4625) followed by a successful logon (4624) within the same 5-minute window. Filters out noisy service accounts (SYSTEM, LOCAL SERVICE, NETWORK SERVICE) and restricts to interactive/network logon types.

```spl
index=main sourcetype=WinEventLog:Security (EventCode=4625 OR EventCode=4624)
| search Account_Name!="SYSTEM" Account_Name!="LOCAL SERVICE" Account_Name!="NETWORK SERVICE"
| eval is_user_login=if(Logon_Type=2 OR Logon_Type=10, 1, 0)
| bin _time span=5m
| stats
    count(eval(EventCode=4625)) as failed_attempts,
    count(eval(EventCode=4624 AND is_user_login=1)) as success_logins,
    values(Source_Network_Address) as src_ip
    by _time, Account_Name, host
| where failed_attempts >= 3 AND success_logins >= 1
```

**Result:** 1 true positive — account `LAB$` with 7 failed attempts + 4 successful logins from `127.0.0.1`

| Screenshot | Description |
|---|---|
| ![Brute Force Correlation Query](screenshots/13_brute_force_refined_query.png) | Final refined SPL with service account filtering and logon type eval |
| ![Brute Force Alert Saved](screenshots/14_brute_force_alert_saved.png) | Saved as scheduled alert in Splunk |

---

### 2. Password Spray Detection
**MITRE:** T1110.003 – Brute Force: Password Spraying

Detects a single source generating failed logon events (4625) across multiple accounts within a short time window — the hallmark of password spraying (low-and-slow, one password across many users).

```spl
index=* EventCode=4625
| stats count by Account_Name, host
```

**Key finding:** 783 total 4624 events; 28 total 4625 events in the lab environment. The `stats count by Account_Name` query (Image 5) revealed `LAB$` generating 23 of 28 failure events — flagging it as anomalous.

| Screenshot | Description |
|---|---|
| ![Failed Logons Raw](screenshots/01_eventcode_4625_failed_logons.png) | 28 EventCode 4625 events — raw failed logon data |
| ![Stats by Account](screenshots/05_4625_stats_by_account_name.png) | Breakdown by Account_Name showing LAB$ with 23 failures |

---

### 3. Ransomware-Like File Access (High Volume Object Access)
**MITRE:** T1486 – Data Encrypted for Impact | T1083 – File and Directory Discovery

Detects accounts performing unusually high volumes of file/object access (EventCode 4663) within a short period — consistent with ransomware enumeration or bulk encryption behaviour.

```spl
index=* EventCode=4663
| stats count by Account_Name
| where count > 20
```

**Result:** 259 total events. Two accounts exceeded the threshold: `LAB$` (52 events) and `socen` (207 events) — `socen` flagged as high-priority anomaly.

| Screenshot | Description |
|---|---|
| ![Object Access Raw](screenshots/06_eventcode_4663_object_access.png) | 259 EventCode 4663 events logged |
| ![High Volume Accounts](screenshots/07_4663_stats_high_volume_accounts.png) | socen account with 207 object access events — ransomware indicator |

---

### 4. AD Group Membership Change
**MITRE:** T1098 – Account Manipulation | T1069 – Permission Groups Discovery

Monitors EventCode 4732 (member added to security-enabled local group) to detect lateral movement via privilege escalation or persistence through group membership modification.

```spl
index=* EventCode=4732
```

**Result:** 12 events detected. Fields extracted: `Group_Name`, `Account_Domain`, `Account_Name`.

| Screenshot | Description |
|---|---|
| ![Group Membership Change](screenshots/03_eventcode_4732_group_membership_change.png) | 12 EventCode 4732 events — AD group modification activity |

---

### 5. New User Account Created
**MITRE:** T1136.001 – Create Account: Local Account

Monitors EventCode 4720 (user account created) to detect persistence via unauthorised account creation.

```spl
index=* EventCode=4720
```

**Result:** 6 events. Fields available: `Account_Expires`, `Account_Name`, `Display_Name`, `Allowed_To_Delegate_To`.

| Screenshot | Description |
|---|---|
| ![User Account Created](screenshots/04_eventcode_4720_user_account_created.png) | 6 EventCode 4720 events — new local accounts created |

---

##  Saved Alerts (Splunk Alerts Dashboard)

Three production-ready alerts were configured as scheduled searches, running every hour:

| Alert Name | Detection Logic | Schedule |
|---|---|---|
| Brute Force Followed by Successful Login | 4625 + 4624 correlation with logon type filtering | Hourly |
| RANSOMWARE | High-volume 4663 object access per account | Hourly |
| Password Spray Detection | 4625 failures across multiple accounts | Hourly |

![Saved Alerts Dashboard](screenshots/08_saved_alerts_dashboard.png)

---

##  MITRE ATT&CK Coverage

| Technique ID | Technique Name | Detection |
|---|---|---|
| T1110.001 | Brute Force: Password Guessing | Brute Force + Successful Login correlation |
| T1110.003 | Brute Force: Password Spraying | Password Spray Detection |
| T1078 | Valid Accounts | Post-brute-force successful logon |
| T1098 | Account Manipulation | EventCode 4732 group change monitoring |
| T1136.001 | Create Account: Local Account | EventCode 4720 monitoring |
| T1486 | Data Encrypted for Impact | High-volume 4663 object access |
| T1083 | File and Directory Discovery | 4663 volume anomaly baseline |

---

##  Key SPL Techniques Used

- `bin _time span=5m` — time-window bucketing for correlation
- `eval(EventCode=4625)` inside `stats count` — conditional counting within a single search
- `values(Source_Network_Address) as src_ip` — multi-value field aggregation
- `search Account_Name!=` — noise reduction / service account exclusion
- `eval is_user_login=if(Logon_Type=2 OR Logon_Type=10, 1, 0)` — logon type classification
- `where count > N` — threshold-based anomaly detection

---

##  Lab Environment

| Component | Details |
|---|---|
| SIEM | Splunk Enterprise 10.2.2 |
| Log Source | WinEventLog:Security (Windows host: LAB) |
| Sourcetype | WinEventLog:Security |
| Index | main |
| Attack Simulation | Manual + scripted Windows event generation |

---

##  Full Screenshot Gallery

| # | Screenshot | Event Code | Description |
|---|---|---|---|
| 1 | ![](screenshots/01_eventcode_4625_failed_logons.png) | 4625 | Raw failed logon events — 28 total |
| 2 | ![](screenshots/02_eventcode_4624_successful_logons.png) | 4624 | Successful logon events — 783 total |
| 3 | ![](screenshots/03_eventcode_4732_group_membership_change.png) | 4732 | AD group membership changes — 12 events |
| 4 | ![](screenshots/04_eventcode_4720_user_account_created.png) | 4720 | New user accounts created — 6 events |
| 5 | ![](screenshots/05_4625_stats_by_account_name.png) | 4625 | Stats breakdown — LAB$ with 23/28 failures |
| 6 | ![](screenshots/06_eventcode_4663_object_access.png) | 4663 | Object access events — 259 total |
| 7 | ![](screenshots/07_4663_stats_high_volume_accounts.png) | 4663 | High-volume filter — socen: 207, LAB$: 52 |
| 8 | ![](screenshots/08_saved_alerts_dashboard.png) | — | 3 saved production alerts, all enabled |
| 9 | ![](screenshots/09_4625_initial_detection.png) | 4625 | Initial 4625 detection build |
| 10 | ![](screenshots/10_4625_stats_by_account_host.png) | 4625 | Stats by account and host |
| 11 | ![](screenshots/11_4625_time_binned_src_ip.png) | 4625 | Time-binned with src_ip extraction |
| 12 | ![](screenshots/12_brute_force_success_correlation.png) | 4625+4624 | First brute force + success correlation |
| 13 | ![](screenshots/13_brute_force_refined_query.png) | 4625+4624 | Refined query with service account filter |
| 14 | ![](screenshots/14_brute_force_alert_saved.png) | — | Alert saved and enabled |

---


