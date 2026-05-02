

##  Use Case 1: Brute Force Followed by Successful Login

###  Query 1
index=main sourcetype=WinEventLog:Security (EventCode=4625 OR EventCode=4624)
| bin _time span=5m
| stats 
    count(eval(EventCode=4625)) as failed_attempts
    count(eval(EventCode=4624)) as success_logins
    values(Source_Network_Address) as src_ip
by _time, Account_Name, host
| where failed_attempts > 3 AND success_logins > 0

---

## Use Case 2: Failed Login Count by Account

###  Query
index=* EventCode=4625
| stats count by Account_Name, host

---

##  Use Case 3: Object Access Activity Monitoring

### 🔎 Query
index=* EventCode=4663
| stats count by Account_Name
| where count > 20

---

##  Use Case 4: Security Group Membership Changes

### 🔎 Query
index=* EventCode=4732

---

##  Use Case 5: User Account Creation Monitoring

### 🔎 Query
index=* EventCode=4720

---

