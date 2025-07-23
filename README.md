<p align="center">
  <a href="https://github.com/Samuel-Cavada" target="_blank">
    <img src="https://img.shields.io/badge/Back_to_Main_Page-000000?style=for-the-badge&logo=github&logoColor=white" alt="Back to Main Page"/>
  </a>
</p>

<h1 align="center">Scenario 1: Virtual Machine Brute Force Detection</h1>

<p align="center">
  <img src="https://img.shields.io/badge/Platform-Azure%20Sentinel-0078D4?style=for-the-badge&logo=microsoftazure&logoColor=white" alt="Cloud Platform" />
  <img src="https://img.shields.io/badge/OS-Windows%2010-0078D6?style=for-the-badge&logo=windows&logoColor=white" alt="OS" />
  <img src="https://img.shields.io/badge/Tool-Microsoft%20Sentinel-00B388?style=for-the-badge&logo=microsoftazure&logoColor=white" alt="Tool" />
  <img src="https://img.shields.io/badge/Tool-Microsoft%20Defender%20for%20Endpoint-2C5EA8?style=for-the-badge&logo=microsoftdefender&logoColor=white" alt="Tool" />
  <img src="https://img.shields.io/badge/Focus-Brute%20Force%20Detection-orange?style=for-the-badge" alt="Focus Area" />
</p>

---

## 📌 Project Objective
> Detect and investigate brute-force login attempts targeting Azure virtual machines using Microsoft Sentinel, Defender for Endpoint telemetry, and KQL queries. Automate alert generation, respond to incidents, and apply NSG hardening based on findings.

---

## 🧰 Tools & Technologies
- **Platform:** Azure
- **OS:** Windows 10
- **Tools:** Microsoft Sentinel, Microsoft Defender for Endpoint, Log Analytics, NSGs
- **Languages/Scripts:** KQL

---

## 🧠 Skills Gained / Focus Areas
- Created Sentinel Analytics Rule to detect brute-force behavior
- Used DeviceLogonEvents to identify repeated login failures
- Mapped remote IP and device entities to incidents
- Performed incident response aligned with NIST 800-61

---

## 🧪 Environment Setup
> Deployed and onboarded a Windows 10 Azure VM to Microsoft Defender for Endpoint. Ensured telemetry was forwarded to Microsoft Sentinel’s Log Analytics Workspace.

![VMBFD1](https://raw.githubusercontent.com/Samuel-Cavada/Scenario-1-Virtual-Machine-Brute-Force-Detection/main/images/VMBFD.jpg)

---

## 🛠️ Walkthrough
1. [Step 1: Create Alert Rule](#step-1-create-alert-rule)
2. [Step 2: Trigger Alert](#step-2-trigger-alert)
3. [Step 3: Work Incident](#step-3-work-incident)
4. [Step 4: Cleanup](#step-4-cleanup)

---

### ✅ Step 1: Create Alert Rule
> Scheduled query to detect brute-force login attempts:

```kql
DeviceLogonEvents
| where ActionType == "LogonFailed" and TimeGenerated > ago(5h)
| summarize EventCount = count() by RemoteIP, DeviceName
| where EventCount >= 10
| order by EventCount
```

> **Analytics Rule Settings:**
- Run every 4 hours
- Lookup data from last 5 hours
- Stop running query after alert generated
- Entity mappings: RemoteIP, DeviceName
- Create incident automatically
- Group alerts into single incident per 24 hours

![VMBFD4](https://raw.githubusercontent.com/Samuel-Cavada/Scenario-1-Virtual-Machine-Brute-Force-Detection/main/images/VMBFD4.jpg)

---

### ✅ Step 2: Trigger Alert
> - Simulated brute-force by failing RDP login multiple times from same IP  
> - Alert was triggered and incident created in Sentinel  
> - Confirmed incident listed under: **Threat Management → Incidents**

![VMBFD1](https://raw.githubusercontent.com/Samuel-Cavada/Scenario-1-Virtual-Machine-Brute-Force-Detection/main/images/VMBFD1.jpg)

---

### ✅ Step 3: Work Incident
> Followed **NIST 800-61** Lifecycle:

**Preparation:**
- Documented roles and processes  
- Verified telemetry and analytic rules were operational  

**Detection & Analysis:**
- Investigated incident using **Actions → Investigate**  
- Viewed entities: multiple Remote IPs targeting two hosts  
- Ran this query to validate no successful logon occurred:

```kql
let TargetDevice = "windows-target-1";
let SuspectIP = "89.116.158.44";
DeviceLogonEvents
| where ActionType == "LogonSuccess"
| where DeviceName == TargetDevice and RemoteIP == SuspectIP
| order by TimeGenerated desc
```

**Containment & Recovery:**
- Locked down NSG to allow only traffic from my public IP  
- No actual successful brute force occurred  
- Drafted corporate policy for VM NSG hardening

**Post-Incident:**
- Recorded timeline and IPs in incident notes  
- Suggested automation of RDP NSG restriction via Azure Policy  
- Closed incident as **True Positive**

![VMBFD6](https://raw.githubusercontent.com/Samuel-Cavada/Scenario-1-Virtual-Machine-Brute-Force-Detection/main/images/VMBFD6.jpg)

---

### ✅ Step 4: Cleanup
> - Deleted incident from **Threat Management → Incidents** (closed filter)  
> - Deleted Analytics Rule from **Configuration → Analytics**  
> - Verified only MY rules and incidents were removed

![VMBFD8](https://raw.githubusercontent.com/Samuel-Cavada/Scenario-1-Virtual-Machine-Brute-Force-Detection/main/images/VMBFD8.jpg)
![VMBFD9](https://raw.githubusercontent.com/Samuel-Cavada/Scenario-1-Virtual-Machine-Brute-Force-Detection/main/images/VMBFD9.jpg)

---

## 📝 Timeline Summary and Findings
- Alert triggered after >10 failed logins from same IP  
- No successful logons occurred  
- NSG locked to restrict public access  
- Policy recommendation documented  

---

## 📎 References
- [DeviceLogonEvents Table](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-devicelogonevents-table)
- [Create Scheduled Query Rule](https://learn.microsoft.com/en-us/azure/sentinel/tutorial-detect-threats-custom)
- [NIST 800-61 Incident Response Guide](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf)
