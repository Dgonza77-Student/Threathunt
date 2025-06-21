# 🚨 Incident Report: Internal Network Scanning Causing Slowdown

**Date of Incident:** June 21, 2025  
**Device Involved:** `khajitwares` (10.0.0.26)  
**User:** _[Redacted]_  
**Detection Method:** Microsoft Defender for Endpoint (MDE)  
**Severity:** High  
**Status:** Confirmed and Investigated

---

## 📌 Summary

An internal host (`khajitwares`) was identified as the source of significant network performance degradation. Investigation revealed the execution of a PowerShell-based port scanning script (`portscan.ps1`) targeting multiple internal IPs and ports within a short period, consistent with observed slowdown reports.

---

## 🕒 Timeline of Events

The server team has noticed a significant network performance degradation on some of their older devices attached to the network. After ruling out external DDoS attacks, the security team suspects something might be going on internally.All traffic originating from within the local network is by default allowed by all hosts. There is also unrestricted use of PowerShell and other applications in the environment. It’s possible someone is either downloading large files or doing some kind of port scanning against hosts in the local network.
Goal: Investigate Cause of Sudden Network Slowdowns


**Initial Query**
To begin my investigation I query device network events with the following KQL Script

```
DeviceNetworkEvents
| where InitiatingProcessFileName == "powershell.exe"
| where RemoteUrl contains "github"
```

![image](https://github.com/user-attachments/assets/9d008a89-b7e4-4eab-a193-727eb814c90a)


Following this scan is when I was first made aware of the Devive "KhajitWares" on the network.

Upon investigation into their network activity I can make out the following information about the user

Device Name: Khajitwares


Timestamp: June 21, 2025, 12:37:36 AM


ActionType: ConnectionSuccess


RemoteIP: 185.199.110.133 → resolves to raw.githubusercontent.com (GitHub asset server)


RemotePort: 443 → secure HTTPS


RemoteUrl: https://raw.githubusercontent.com/.../portscan.ps1


LocalIP: 10.0.0.26


LocalPort: 53690 (ephemeral port, typical for outbound traffic)


![image](https://github.com/user-attachments/assets/d9a358bd-ce12-427e-a401-bedba851d2d4)

As well as 

![image](https://github.com/user-attachments/assets/b62f6352-96ab-45cb-8cd2-cd27f19654c1)

The above image details a command ran on Jun 21st at 12:37 am eastern standard time.

The following command used a powershell bypass execution policy to download a script from github named “portscan.ps1”
And saved it to C:\programdata\portscan.ps1



After witnessing this log and several others like it from the same device name, we can now reasonably suspect this user to be the perp in the network slowdowns and begin to investigate the matter

Device “Khajitwares” powershell commands show multiple connections to Github to download different tools and command line usage with invoke requests which are strong indicators of initial payload delivery


**Note**
 Port Scanning often generates a high volume of connection attempts to different IPS and Ports- which aligns with network congestion symptoms

 
The current investigation standing has:

**Indicators of Behavior:** Sus powershell Downloads
**Potential Tools:** Data Exfiltration/Port Scanners
**Source Device Name:** “KhajitWares”
**Witnessed pattern**
**Matching Symptoms:** Unexplained network degradation reported by the server team


I am now go to move to investigate a little further into the user and their activity on the network for any telling indicators of compromise

With their activities being within the last 24 hours I run the following KQL query to see what else they have been doing within the past 24 hours

```
DeviceNetworkEvents
| where DeviceName == "khajitwares"
| where Timestamp > ago(1d)  // adjust as needed
| project Timestamp, RemoteIP, RemotePort, RemoteUrl, ActionType, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

![image](https://github.com/user-attachments/assets/7a415ea0-5b40-4927-82b9-2fd1bc0b291c)

After running the command I can see that Device name “Khajitwares” was active until 3:50 am eastern standard time on the server. I begin to retrace his steps and analyze logs starting from their powershell port scanner download at Jun 21, 2025 12:34:49 AM  

I download the CSV of the logs and make them more digestible before analyzing them and coloring in strange activity 
[Filtered Khajit logs](https://drive.google.com/file/d/1CqhSg7hAYzh0MfTSLHcpKzUyC84rSupK/view?usp=sharing)

In the following document we can see at 0:37 (12:37) am est the user downloaded a port scanning script from github and then began to execute it on the server

We know this because of the flurry of failed connections witnessed between 12:37 am and 12:39 am.
![image](https://github.com/user-attachments/assets/3651120f-bfde-4e3b-ba9b-c91030881774)

At 12:39 am the user found their first open port and got a connection success before continuing to scan and receive more failures 

![image](https://github.com/user-attachments/assets/cf794022-53d7-4f0b-8007-f2e040be9be0)


Full Colored Logs (Between 12:39 to end of port scanning) for reference 
[Colored Khajit Logs for reference](https://docs.google.com/spreadsheets/d/163XeYczty5GO5xIxWHCLoZhg60DOD61hQJAyEaWFx_4/edit?usp=sharing)

During this whole process we can see -ExecutionPolicy Bypass -File C:\programdata\portscan.ps1 being executed



| Time (UTC)         | Event Description                                                                                  |
|--------------------|---------------------------------------------------------------------------------------------------|
| 12:37:36 AM        | PowerShell connection to GitHub initiated via `Invoke-WebRequest`                                  |
| 12:37:37 AM        | Successful HTTPS connection to `raw.githubusercontent.com` to retrieve `portscan.ps1`              |
| 12:38:00 - 12:39:50 AM | Port scan script (`portscan.ps1`) executed with `-ExecutionPolicy Bypass`                     |
| 12:38:10 - 12:39:50 AM | Burst of failed connection attempts from PowerShell to multiple internal IPs and ports         |
| 12:39:13 AM        | Some successful connections observed, indicating service discovery                                 |
| 12:40 AM onward    | Activity subsides; system returns to regular telemetry traffic                                     |

---

## 🔍 Key Findings

- Unauthorized download and execution of a PowerShell script from GitHub
- The script triggered a flood of outbound connection attempts to internal IP addresses (`10.0.0.x`)
- Targeted service ports included `21`, `22`, `23`, `80`, `443`, `445`, `3389`, etc.
- Activity strongly correlated with network performance issues reported by the server team

---

## 🎯 MITRE ATT&CK Mapping

| Technique ID  | Name                        | Description                              |
|---------------|-----------------------------|------------------------------------------|
| T1059.001     | PowerShell                  | Execution of PowerShell with bypass flag |
| T1105         | Remote File Copy            | Download of script from GitHub           |
| T1046         | Network Service Scanning    | Internal scanning for open services      |

---

## ✅ Recommended Actions

### 🛡 Immediate Response

- [ ] Isolate `khajitwares` from network access
- [ ] Remove `portscan.ps1` from `C:\programdata\`
- [ ] Reimage device if compromise is suspected
- [ ] Reset user credentials associated with the device

### 🧪 Further Investigation

- [ ] Query for lateral movement or privilege escalation
- [ ] Review logs from other scanned hosts for follow-up connections
- [ ] Check for similar scripts or behaviors on other endpoints

### 🔐 Preventive Measures

- [ ] Enforce PowerShell execution restrictions via GPO
- [ ] Block outbound PowerShell file downloads via Defender ASR rules
- [ ] Alert on suspicious command-line flags and execution from `C:\programdata\`
- [ ] Review security training and acceptable use policy with user

---

## 🧾 Evidence Summary

- `powershell.exe` invoked with:  
  `-ExecutionPolicy Bypass -File C:\programdata\portscan.ps1`
- Network logs showing 20+ internal IPs targeted
- Ports probed include commonly used and vulnerable services
- GitHub URL used: `https://raw.githubusercontent.com/....`

---

> 📁 _All log screenshots and extracted CSVs are archived in the investigation folder for documentation._

