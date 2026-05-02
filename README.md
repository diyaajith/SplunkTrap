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
| bin _time span=5m
| stats 
    count(eval(EventCode=4625)) as failed_attempts
    count(eval(EventCode=4624)) as success_logins
    values(Source_Network_Address) as src_ip
by _time, Account_Name, host
| where failed_attempts > 3 AND success_logins > 0
```

**Result:** 1 true positive — account `LAB$` with 6 failed attempts + 11 successful logins from `127.0.0.1`


<img width="456" height="219" alt="image" src="https://github.com/user-attachments/assets/ead36d08-192c-40e5-87d4-17b30404351b" />




---

### 2. Password Spray Detection
**MITRE:** T1110.003 – Brute Force: Password Spraying

Detects a single source generating failed logon events (4625) across multiple accounts within a short time window — the hallmark of password spraying (low-and-slow, one password across many users).



```spl
index=* EventCode=4625
| stats count by Account_Name, host
```


<img width="455" height="234" alt="image" src="https://github.com/user-attachments/assets/c95fd107-2cbd-497e-9935-de26b00b8eb3" />



```spl
index=* EventCode=4625
| stats count by Account_Name, host
```



<img width="458" height="235" alt="image" src="https://github.com/user-attachments/assets/97176ff3-9a6e-4ed3-a5ca-41d10e4f3c96" />




**Key finding:** Total 824 events in the lab environment.
---

### 3. Ransomware-Like File Access (High Volume Object Access)
**MITRE:** T1486 – Data Encrypted for Impact | T1083 – File and Directory Discovery

Detects accounts performing unusually high volumes of file/object access (EventCode 4663) within a short period — consistent with ransomware enumeration or bulk encryption behaviour.

```spl
index=* EventCode=4663
| stats count by Account_Name
| where count > 20
```

<img width="458" height="219" alt="image" src="https://github.com/user-attachments/assets/4473e446-3989-44f7-9843-1f7236bed158" />



**Result:** 259 total events. Two accounts exceeded the threshold: `LAB$` (52 events) and `socen` (207 events) — `socen` flagged as high-priority anomaly.

---

### 4. AD Group Membership Change
**MITRE:** T1098 – Account Manipulation | T1069 – Permission Groups Discovery

Monitors EventCode 4732 (member added to security-enabled local group) to detect lateral movement via privilege escalation or persistence through group membership modification.

```spl
index=* EventCode=4732
```

<img width="464" height="235" alt="image" src="https://github.com/user-attachments/assets/1f427b77-6453-4a9e-a4d4-0198abb32a9d" />


**Result:** 12 events detected. Fields extracted: `Group_Name`, `Account_Domain`, `Account_Name`.

---

### 5. New User Account Created
**MITRE:** T1136.001 – Create Account: Local Account

Monitors EventCode 4720 (user account created) to detect persistence via unauthorised account creation.

```spl
index=* EventCode=4720
```

<img width="457" height="234" alt="image" src="https://github.com/user-attachments/assets/180a4e5e-116a-4147-abe5-63878e234478" />


**Result:** 6 events
System: LAB
Insight: Multiple user account creations; requires validation for legitimacy.

---

##  Saved Alerts (Splunk Alerts Dashboard)

Three production-ready alerts were configured as scheduled searches, running every hour:

<img width="463" height="218" alt="image" src="https://github.com/user-attachments/assets/fea0a312-c858-4b4c-9882-0a20f2875101" />


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



