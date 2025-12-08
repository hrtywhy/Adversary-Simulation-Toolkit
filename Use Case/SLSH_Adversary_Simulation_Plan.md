# SLSH (Scattered LAPSUS$ Hunters) Adversary Simulation Plan

## 🚨 Threat Profile
**SLSH** is a federated cybercriminal alliance merging the operations and expertise of **Scattered Spider**, **LAPSUS$**, and **ShinyHunters**. They are known for aggressive social engineering, initial access brokering (IAB), and extortion-as-a-service.

**Objective**: Gain initial access via identity compromise, move laterally to high-value assets, exfiltrate sensitive data, and deploy ransomware (ShinySp1d3r) for extortion.

## 🗺️ Attack Flow

### Phase 1: Initial Access & Reconnaissance
*Focus: Identity Compromise and Social Engineering*
- **Technique**: **T1566.004 (Phishing: Spearphishing Voice)** - "Vishing" employees to reset passwords or install RMM tools.
- **Technique**: **T1621 (Multi-Factor Authentication Request Generation)** - MFA Fatigue / Bombing to annoy users into accepting prompts.
- **Technique**: **T1078 (Valid Accounts)** - Purchasing credentials from Initial Access Brokers (IABs).
- **Simulation**:
  - Simulate vishing calls (using text-to-speech or pre-recorded scripts) targeting helpdesk.
  - Attempt MFA fatigue on test accounts.

### Phase 2: Execution & Persistence
*Focus: Living off the Land and Session Hijacking*
- **Technique**: **T1204.002 (User Execution: Malicious File)** - Tricking users into downloading remote access tools (AnyDesk, TeamViewer).
- **Technique**: **T1550.004 (Use Alternate Authentication Material: Web Session Cookie)** - Hijacking Okta/SSO sessions.
- **Technique**: **T1098 (Account Manipulation)** - Adding a new MFA device to a compromised account for persistence.
- **Simulation**:
  - Deploy a benign "remote support" tool (e.g., a renamed netcat or legitimate AnyDesk binary).
  - Extract session cookies from a browser (using tools like `CookieKatz` or `SharpChrome`).

### Phase 3: Privilege Escalation & Lateral Movement
*Focus: Cloud and Hybrid Identity Abuse*
- **Technique**: **T1078.004 (Valid Accounts: Cloud Accounts)** - Pivoting from on-prem to Cloud (AWS/Azure) or vice versa.
- **Technique**: **T1021.001 (Remote Services: Remote Desktop Protocol)** - Moving laterally via RDP.
- **Technique**: **T1570 (Lateral Tool Transfer)** - Using `deployViaWMI` or `deployViaSCM` to spread payloads.
- **Simulation**:
  - Use `Rubeus` or `Mimikatz` to harvest credentials.
  - Attempt lateral movement using `WMI` (e.g., `Invoke-WmiMethod`).

### Phase 4: Exfiltration & Impact
*Focus: Data Theft and Encryption*
- **Technique**: **T1567 (Exfiltration Over Web Service)** - Uploading data to Mega.nz or similar file-sharing sites.
- **Technique**: **T1486 (Data Encrypted for Impact)** - Deploying **ShinySp1d3r** ransomware (simulated).
- **Simulation**:
  - Compress a dummy dataset and exfiltrate via `rclone` to a cloud bucket.
  - Execute a "mock" ransomware script that renames files (e.g., `.shiny`) and drops a ransom note without actual encryption.

## 🛠️ Tools Required
- **Recon**: `BloodHound` (for identifying high-value targets)
- **Access**: `Evilginx2` (for session token theft), `Social-Engineer Toolkit (SET)`
- **Lateral**: `Impacket` (wmiexec, smbexec), `Rubeus`
- **Exfiltration**: `Rclone`, `MEGAsync`
