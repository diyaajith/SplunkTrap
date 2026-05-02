# 🔍 Splunk Security Processing & Analysis (SPA)

## 📌 Use Case 1: Brute Force Followed by Successful Login

### 🔎 Query
index=main sourcetype=WinEventLog:Security (EventCode=4625 OR EventCode=4624)
| bin _time span=5m
| stats 
    count(eval(EventCode=4625)) as failed_attempts
    count(eval(EventCode=4624)) as success_logins
    values(Source_Network_Address) as src_ip
by _time, Account_Name, host
| where failed_attempts > 3 AND success_logins > 0

### ✅ Result Summary
Detects accounts with multiple failed login attempts followed by a success within 5 minutes.

### 🚨 Insight
Indicates potential brute-force attack leading to account compromise.

---

## 📌 Use Case 2: Failed Login Count by Account

### 🔎 Query
index=* EventCode=4625
| stats count by Account_Name, host

### ✅ Result Summary
Aggregates total failed login attempts per account and host.

### 🚨 Insight
Helps identify targeted accounts and password spray attempts.

---

## 📌 Use Case 3: Object Access Activity Monitoring

### 🔎 Query
index=* EventCode=4663
| stats count by Account_Name
| where count > 20

### ✅ Result Summary
Filters accounts with more than 20 object access events.

### 🚨 Insight
High activity may indicate data exfiltration or unauthorized access.

---

## 📌 Use Case 4: Security Group Membership Changes

### 🔎 Query
index=* EventCode=4732

### ✅ Result Summary
Captures events where users are added to security groups.

### 🚨 Insight
Possible privilege escalation activity.

---

## 📌 Use Case 5: User Account Creation Monitoring

### 🔎 Query
index=* EventCode=4720

### ✅ Result Summary
Tracks newly created user accounts.

### 🚨 Insight
Important for detecting unauthorized account creation or persistence.

---

## 📊 Overall Detection Strategy

| Event Code | Description              | Threat Type                  |
|------------|--------------------------|------------------------------|
| 4625       | Failed Login             | Brute Force / Password Spray |
| 4624       | Successful Login         | Account Access               |
| 4663       | Object Access            | Data Exfiltration            |
| 4732       | Group Membership Change  | Privilege Escalation         |
| 4720       | User Account Creation    | Persistence                  |

---

## 🚨 Key Takeaways

- Combine 4625 + 4624 → Detect real compromises  
- Monitor high-frequency events → Spot anomalies  
- Track account & privilege changes → Detect lateral movement  

---

## 📌 Recommendation

- Convert queries into Splunk alerts  
- Set thresholds (failed logins > 3, object access > 20)  
- Use dashboards for real-time monitoring  
