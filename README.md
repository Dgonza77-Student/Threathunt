# Windows Server Threat Hunt: RDP Exposure & MITRE Mapping

## 1. Preparation

**Goal**: Investigate suspicious activity on a VM exposed to the public internet.

**Scenario**: During routine security checks, it was discovered that a Windows VM (`windows-target-1`) handling DNS and other shared services had been publicly exposed. The goal was to identify brute-force attempts, determine the attacker's method, and assess any successful intrusions using MITRE ATT\&CK mappings.

**Hypothesis**: If the VM was exposed to the internet, threat actors may have attempted brute-force login attempts or executed malicious scripts to gain a foothold.



---

## 2. Data Collection & Analysis


## Step 1: Confirm VM is Internet Facing
First we confirm the VM was exposed to the internet by running the following command
```DeviceInfo
| where DeviceName == "windows-target-1"
| where IsInternetFacing == true
| order by Timestamp desc
```

![image](https://github.com/user-attachments/assets/b2bd27a9-6517-44f9-9579-75f59b6e00d2)

The following command confirms the VM has been internet facing for several days

### Step 2: Identify Brute Force through failed logons

```kql
DeviceLogonEvents
| where DeviceName == "windows-target-1"
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonFailed"
| where isnotempty(RemoteIP)
| summarize Attempts = count() by ActionType, RemoteIP, DeviceName
| order by Attempts
```
![image](https://github.com/user-attachments/assets/e52b7e12-5fb2-4ec6-af6f-5c16f1314a3c)

**Findings**:

The above screenshot shows a query that links the windows-target-1 machine “interactions” to that of t-100 “brute force attacks” according to MITRE ATTACK mapping. We can see a flurry of different remote IPS and how many times they attempted and failed to log into “Windows-target-1”. The most prominent of these being 109.205.213.154 within the last 7 days. 

**T1110: Brute Force confirmed**.

### Step 3: Determine Attack Method (RDP or SMB?)

Now that I know the kind of attack this person did, I am now trying to understand the method they used to try and conduct it.

I ran several queries to confirm if this particular IP attempted to do so via the servers RDP (Remote desktop Protocol) but came to no avail. 

```kql
let RemoteIPsInQuestion = dynamic(["109.205.213.154"]);
DeviceLogonEvents
| where LogonType has_any("RemoteInteractive")
| where ActionType == "LogonFailed"
| where RemoteIP in (RemoteIPsInQuestion)
```
![image](https://github.com/user-attachments/assets/9e6a78b5-5f63-4fd7-a566-3c97cae977de)


```kql
let RemoteIPsInQuestion = dynamic(["109.205.213.154"]);
DeviceLogonEvents
| where LogonType has_any("RemoteInteractive")
| where ActionType == "LogonSuccess"
| where RemoteIP in (RemoteIPsInQuestion)
```

**Result**: No RDP-based attacks observed (LogonType 10).

To find out the network type I run the following query

```kql
DeviceLogonEvents
| where DeviceName == "windows-target-1"
| where RemoteIP == "109.205.213.154"
| where ActionType == "LogonFailed"
| summarize Attempts = count() by LogonType
```
![image](https://github.com/user-attachments/assets/ad7fde4c-dca6-4598-82a8-d675fd796b3f)


**Result:** LogonType 3 (Network) — T1021.002 (SMB) or T1021.006 (WinRM) attempt observed. No evidence of RDP (LogonType 10) activity.

**Interpretation:** The attacker attempted brute-force logins using network-based authentication protocols (e.g., SMB or WinRM), not interactive RDP sessions.

![image](https://github.com/user-attachments/assets/a7ed6407-fe4e-4e18-a35b-24db80ba4768)

The attacker (IP: 109.205.213.154) conducted a brute-force attack using Network logon attempts (LogonType 3), which typically target SMB or remote services like WinRM. No successful logins were observed, and no RDP activity (LogonType 10) was detected. This indicates a failed brute-force attempt via network-based protocols (e.g., SMB or WinRM), with no evidence of RDP (Remote Desktop) usage.

## Windows Logon Types Explained

| Logon Type | Description                                 | Typical Use Cases                                | Example Protocols           | Related MITRE ATT&CK Techniques           |
|------------|---------------------------------------------|--------------------------------------------------|-----------------------------|-------------------------------------------|
| 2          | Interactive                                 | Local login at physical machine (console login)  | N/A                         | T1078 – Valid Accounts                    |
| 3          | Network                                     | Remote login without desktop session             | SMB, WinRM, WMI             | T1021.002 – SMB<br>T1021.006 – WinRM     |
| 4          | Batch                                       | Scheduled tasks                                  | Task Scheduler              | T1053.005 – Scheduled Task                |
| 5          | Service                                     | Logon by a service account                       | Windows Services            | T1543.003 – Windows Service               |
| 7          | Unlock                                      | Reconnect after session lock                     | N/A                         | T1078 – Valid Accounts                    |
| 8          | NetworkCleartext                           | Authentication with cleartext credentials        | IIS, Basic Auth             | T1557.002 – LLMNR/NBT-NS Spoofing (if abused) |
| 9          | NewCredentials (RunAs)                      | Logon with explicit credentials (no delegation)  | `runas` command             | T1078 – Valid Accounts                    |
| 10         | RemoteInteractive (RDP)                     | Remote Desktop session                           | RDP (port 3389)             | T1021.001 – Remote Services: RDP          |
| 11         | CachedInteractive                          | Logon with cached credentials                    | Laptop disconnected from domain | T1078 – Valid Accounts                |

> **Note:** Logon Type 3 (Network) is the most common for remote attacks and includes SMB, WinRM, and WMI — all frequently abused in lateral movement and brute-force attempts.


---

### Step 4: Network Activity

Having ruled out RDP as the attack vector, I turned to analyzing the ports targeted by the attacker to determine the underlying protocol used in the brute-force attempts.

```kql
let AttackerIP = "109.205.213.154";
DeviceNetworkEvents
| where DeviceName == "windows-target-1"
| where RemoteIP == AttackerIP
| where RemoteIPType == "Public"
| project Timestamp, RemoteIP, LocalPort, Protocol, ActionType, InitiatingProcessFileName, ReportId
| order by Timestamp desc
```

**Findings**:

The attacker at IP 109.205.213.154 initiated multiple inbound connections to port 3389 (RDP) on windows-target-1. These connections were accepted, confirming that the RDP service was exposed to the internet. While no corresponding successful or failed RemoteInteractive (LogonType 10) events were recorded, the activity strongly suggests reconnaissance or brute-force attempts against the RDP interface. This may indicate a failure in RDP logon telemetry or NLA-based blocking before credential logging occurred.

![image](https://github.com/user-attachments/assets/2088cee8-edb5-4695-b949-611bea4df876)


---

### Step 5: PowerShell & CMD Investigation

To finish my investigation for MITRE mappings I am going to run KQL queries to check common mappings

**For T1059 – Command and Scripting Interpreter**
**Goal: Look for PowerShell or cmd-based execution**

```kql
DeviceProcessEvents
| where DeviceName == "windows-target-1"
| where FileName in~ ("powershell.exe", "cmd.exe")
| project Timestamp, FileName, ProcessCommandLine, InitiatingProcessFileName, AccountName
| order by Timestamp desc
```

Note: Running this command does not exactly mean that the server is being attacked. It only means that Powershell or commands are being run. In order to ensure we are noting attacks I will export the logs to an excel file and parse through them for signs of malicious code.

[T1059 Excel Report]([T1059Combing.csv - Google Drive](https://drive.google.com/file/d/12EhQjHs5pTk74ZLQF3jwrq9O9NGTFFrM/view))

The above excel report contains 5862 entries of logs within the last 30 days to “Windows-target-1”

Within these 5862 logs I was able to determine that 1819 were suspicious of some kind due to parsing the file for high confidence indicators such as the ones listed below


[Sus Powershell Logs]([Suspicious_PowerShell_Logs.xlsx - Google Drive](https://drive.google.com/file/d/15HbzqdDZAfzYO0B4vqELTDiJEvG5-9FT/view))

## ⚠️ Suspicious PowerShell & LOLBin Indicators

| **Indicator**                                | **Why It Matters**                                                                 |
|----------------------------------------------|-------------------------------------------------------------------------------------|
| `-EncodedCommand`                            | Used to obfuscate PowerShell commands; common in malware and post-exploitation     |
| `Invoke-WebRequest`, `Invoke-Expression`, `iex` | Downloads and runs remote code — classic malicious behavior                       |
| `New-Object Net.WebClient`                   | Creates a web client object, often used to pull down payloads                      |
| Use of `curl`, `wget`, raw `http/https` URLs | Indicates outbound connections or remote script downloads                          |
| `certutil`, `bitsadmin`                      | Living-off-the-land binaries often abused for staging or downloading payloads      |
| Launched by unknown/odd parent processes (e.g., `gc_worker.exe`) | Unusual for system-initiated PowerShell; suggests automation or exploitation chain |


**PowerShell Execution Summary**:

* 5,862 total entries
* 1,819 flagged as suspicious (e.g., -EncodedCommand, iex, web calls)
* 290 base64 EncodedCommand entries, all decoded to: `[Environment]::OSVersion.Version`

**MITRE Confirmed**:

* **T1059.001: PowerShell Execution** ✅
* **T1082: System Info Discovery** ✅




**CMD Analysis**:

* Initiated mostly by `healthservice.exe`
* Executed under SYSTEM account
* Maintenance scripts only



[CMD LOGS]([CMD_Execution_Logs.csv - Google Drive](https://drive.google.com/file/d/1PaszexaUP4b6ZpVtrmAe89_LEGVBfO0N/view))

After parsing through the logs we found several, if not nearly all, to be diagnostic or maintenance scripts, likely part of the Azure VM agent (Microsoft.Compute) or internal health monitoring tools.


Commands like StartTracing.cmd ERR and package plugin paths suggest performance tracing or system telemetry.


Initiating Process:


Most executions were triggered by healthservice.exe or another cmd.exe, not a user or attacker process.


Execution Context:


All run under the system account, typical for internal services.


**MITRE Verdict**:

* **T1059.003: CMD** — **❌ Not Confirmed**

 There is no evidence of attacker-controlled or user-initiated cmd.exe execution. All observed usage is consistent with legitimate system processes.


**T1046 – Network Service Scanning**

I run the following KQL Command


```DeviceNetworkEvents
| where DeviceName == "windows-target-1"
| where ActionType == "ConnectionSuccess"
| where RemoteIPType == "Public"
| summarize UniquePorts = dcount(RemotePort),
          Attempts = count(),
          Ports = make_set(RemotePort),
          Targets = make_set(RemoteIP)
    by InitiatingProcessFileName, bin(Timestamp, 5m), DeviceName
| where UniquePorts > 10
| order by Timestamp desc
```
![image](https://github.com/user-attachments/assets/110c839c-b769-47b5-afc3-e9f69ad96592)


❌ No Evidence of T1046 – Network Service Scanning


How can the attacker not use port scan patterns across multiple ports

1. The Attacker Already Knows the Target
2. They’re Using a Focused Payload
  - The [Environment]::OSVersion.Version command tells us they’re already inside or have access to a system
3. They’re Being Quiet (OpSec-aware)



---

## 3. MITRE Technique Summary

### ✅ Confirmed

| Tactic            | Technique                    | ID        | Reason                                 |
| ----------------- | ---------------------------- | --------- | -------------------------------------- |
| Initial Access    | Remote Services: RDP         | T1021.001 | Repeated port 3389 hits                |
| Credential Access | Brute Force                  | T1110     | 119+ failed attempts                   |
| Execution         | PowerShell (Scripting)       | T1059.001 | 1,800+ suspicious executions           |
| Discovery         | System Information Discovery | T1082     | All EncodedCommand decoded to OS check |

### ❌ Not Confirmed

| Tactic          | Technique                    | ID        | Reason                           |
| --------------- | ---------------------------- | --------- | -------------------------------- |
| Execution       | CMD (Command & Scripting)    | T1059.003 | Only maintenance scripts         |
| Persistence     | Valid Accounts               | T1078     | No successful logons             |
| Discovery       | Network Scanning             | T1046     | No port sweep activity           |
| Defense Evasion | Obfuscated Files/Information | T1027     | No advanced payloads or layering |

---

## 4. Timeline Generation

### KQL Queries for Timeline

```kql
// 1. Logon Events
DeviceLogonEvents
| where Timestamp > ago(30d)
| where LogonType has_any("RemoteInteractive", "Network", "Interactive")
| where ActionType has_any("LogonFailed", "LogonSuccess")
| project Timestamp, DeviceName, AccountName, RemoteIP, LogonType, ActionType
```

```kql
// 2. RDP Activity
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where LocalPort == 3389 or RemotePort == 3389
| where ActionType == "ConnectionSuccess"
| project Timestamp, DeviceName, InitiatingProcessFileName, RemoteIP, RemotePort, LocalPort, Protocol
```

```kql
// 3. Port Scan Detection
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where ActionType == "ConnectionSuccess"
| summarize UniquePorts = dcount(RemotePort),
          Attempts = count(),
          Ports = make_set(RemotePort),
          Targets = make_set(RemoteIP)
    by InitiatingProcessFileName, bin(Timestamp, 5m), DeviceName
| where UniquePorts > 10
| order by Timestamp desc
```

[MITRE FULL TIMELINE](https://drive.google.com/file/d/1AT4lulXjJWCtQd1fHQfjBMQzYtVGJRet/view)

### Why Some Events Lack IPs:

| Log Type              | IP Shown? | Reason                   |
| --------------------- | --------- | ------------------------ |
| PowerShell Commands   | ❌         | Local execution only     |
| Logon Events (Remote) | ✅         | Captures remote origin   |
| CMD Scripts           | ❌         | Local system tasks       |
| RDP Connections       | ✅         | Tracked via network logs |

---

## ✅ Final Status Check

### Confirmed Techniques

| Tactic            | Technique             | ID        |
| ----------------- | --------------------- | --------- |
| Initial Access    | RDP (Remote Services) | T1021.001 |
| Credential Access | Brute Force           | T1110     |
| Execution         | PowerShell            | T1059.001 |
| Discovery         | System Info Discovery | T1082     |

### Ruled Out

| Tactic          | Technique          | ID        |
| --------------- | ------------------ | --------- |
| Execution       | CMD (Command Line) | T1059.003 |
| Persistence     | Valid Accounts     | T1078     |
| Discovery       | Network Scanning   | T1046     |
| Defense Evasion | Obfuscation        | T1027     |

---

## 🎓 Lessons Learned & Improvements

### Lessons

* PowerShell telemetry is crucial for catching silent recon attempts
* RDP logging must be validated end-to-end, as no LogonType 10 events were captured
* MITRE mapping helps quantify and organize threat actor behavior

### Improvements

* Enable deeper CMD telemetry (include command lines)
* Trigger alerts on EncodedCommand w/ unknown parent processes
* Auto-block IPs with >25 login failures in 5 mins

---

