# Threat Event (Brute Force Authentication)
**Internal Network Brute-Force Attack from IP 10.0.0.8**

---

## Steps the "Bad Actor" took to Create Logs and IoCs:
1. Used IP `10.0.0.8` to initiate hundreds of remote authentication attempts against `sb-edr-lab`
2. Attempted logins using a large variety of usernames (`administrator`, `nessus}`, `db2admin`, etc.)
3. All login attempts failed — no successful access recorded
4. Attack occurred over a span of ~20 days, from **May 25, 2025** to **June 14, 2025**
5. Targeted service was `LogonType = Network` (likely SMB-based authentication)

---

## Steps Taken
1. Ran KQL queries in Microsoft 365 Defender Advanced Hunting to identify brute-force activity.
2. Filtered for failed `LogonType = Network` events across all devices.
3. Isolated top offending IPs and verified volume of failed logins on `sb-edr-lab`.
4. Verified no `LogonSuccess` activity occurred from the same IP.
5. Documented timeline, IoCs, and usernames targeted.

---

## Chronological Events
- **May 25, 2025** – First brute-force activity from IP `10.0.0.8` targeting `sb-edr-lab`.
- **May 25 – June 14, 2025** – Persistent failed login attempts using different usernames.
- **June 14, 2025** – Last observed failed attempt from `10.0.0.8`.
- No successful logons were detected at any point.

---

## Summary
A brute-force attack originating from internal IP `10.0.0.8` targeted the system `sb-edr-lab` over a 20-day span. A total of 88 unique usernames were used across hundreds of login attempts. No successful logins occurred. The attack appears to be a password spray attempt likely using automated tooling.

---

## Tables Used to Detect IoCs:

| **Parameter** | **Description** |
|---------------|------------------|
| **Name** | DeviceLogonEvents |
| **Info** | https://learn.microsoft.com/en-us/microsoft-365/security/defender-xdr/advanced-hunting-devicelogonevents-table |
| **Purpose** | Used to detect failed logon attempts from external/internal IPs and identify brute-force behavior. |

| **Parameter** | **Description** |
|---------------|------------------|
| **Name** | DeviceInfo |
| **Info** | https://learn.microsoft.com/en-us/microsoft-365/security/defender-xdr/advanced-hunting-deviceinfo-table |
| **Purpose** | Used to confirm hostname (`sb-edr-lab`), sensor activity, and OS context for target machine. |

---

## Related Queries:
```kql
// Broad view: failed network logons across the environment
DeviceLogonEvents
| where ActionType == "LogonFailed"
| where LogonType == "Network"
| summarize FailedAttempts = count() by RemoteIP, DeviceName
| order by FailedAttempts desc
```
![image](https://github.com/user-attachments/assets/34f2949b-fe07-45eb-9985-f2ec75f7853a)

```
// Drill into the offending IP (10.0.0.8) and get full account list
DeviceLogonEvents
| where RemoteIP == "10.0.0.8"
| where ActionType == "LogonFailed"
| summarize FailedAttempts = count(), FirstSeen = min(Timestamp), LastSeen = max(Timestamp) 
    by AccountName, LogonType, DeviceName, RemoteIP
| order by FailedAttempts desc
```
![image](https://github.com/user-attachments/assets/11cfc7e1-ad43-4b66-8cfe-d5da72e90fa3)

```
DeviceLogonEvents
| where DeviceName == "sd-edr-lab"
| where ActionType == "LogonSuccess"
![image](https://github.com/user-attachments/assets/359c0726-c88b-41e9-bec7-6d6c98490224)
```

![image](https://github.com/user-attachments/assets/11abd0e6-c666-4f0d-bb1c-2c090148497f)

---

## Created By:
- **Author Name**: Daniel Gonzalez  
- **Author Contact**: https://www.linkedin.com/in/dgonza77  
- **Date**: June 23, 2025

## Validated By:
- **Reviewer Name**:
- **Reviewer Contact**:  
- **Validation Date**:  

---

## Additional Notes:
- No logon attempts were successful. However, multiple high-risk usernames were targeted (`administrator`, `db2admin`, random strings).
- The offending IP may be internal. Requires investigation for misconfiguration or compromise.

---

## Revision History:

| **Version** | **Changes** | **Date** | **Modified By** |
|-------------|-------------|----------|------------------|
| 1.0 | Initial draft | June 23, 2025 | Daniel Gonzalez |
