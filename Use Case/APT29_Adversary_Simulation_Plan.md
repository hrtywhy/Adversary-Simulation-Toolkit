# APT29 (Cozy Bear) Adversary Simulation Plan

## 🚨 Threat Profile
**APT29** (also known as **Cozy Bear**, **The Dukes**, **Yttrium**, **Nobelium**) is a state-sponsored threat actor attributed to Russia's Foreign Intelligence Service (SVR). They are characterized by stealth, patience, and sophisticated supply chain attacks (e.g., SolarWinds).

**Objective**: Long-term espionage, data theft, and maintaining persistent access to government and diplomatic networks.

## 🗺️ Attack Flow

### Phase 1: Initial Access
*Focus: Supply Chain and Valid Accounts*
- **Technique**: **T1195.002 (Supply Chain Compromise: Compromise Software Supply Chain)** - Injecting malicious code into legitimate software updates (simulated via modified DLLs).
- **Technique**: **T1078 (Valid Accounts)** - Password spraying and leveraging compromised credentials.
- **Technique**: **T1133 (External Remote Services)** - Exploiting public-facing applications or VPNs.
- **Simulation**:
  - Perform a low-and-slow password spray attack against a test user list.
  - Simulate a "trojanized" update by replacing a benign binary with a callback beacon.

### Phase 2: Execution & Persistence
*Focus: Stealthy Implants*
- **Technique**: **T1059.001 (Command and Scripting Interpreter: PowerShell)** - Using encoded PowerShell commands.
- **Technique**: **T1547.001 (Boot or Logon Autostart Execution: Registry Run Keys)** - Persistence via Registry.
- **Technique**: **T1098.002 (Account Manipulation: Exchange Email Delegate)** - Granting mailbox permissions to an adversary-controlled account.
- **Simulation**:
  - Execute a base64 encoded PowerShell stager.
  - Add a persistence entry to `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`.

### Phase 3: Privilege Escalation & Lateral Movement
*Focus: Golden SAML and Cloud Pivoting*
- **Technique**: **T1558.003 (Steal or Forge Kerberos Tickets: Kerberoasting)**.
- **Technique**: **T1484.002 (Domain Policy Modification: Group Policy Modification)**.
- **Technique**: **T1606.002 (Forge Web Credentials: SAML Tokens)** - "Golden SAML" attack to forge authentication tokens for cloud services.
- **Simulation**:
  - Use `Rubeus` to perform Kerberoasting.
  - Simulate Golden SAML by generating a forged SAML token (using `AADInternals` or similar in a lab).

### Phase 4: Collection & Exfiltration
*Focus: Cloud Data and Email*
- **Technique**: **T1114.002 (Email Collection: Remote Email Collection)** - Accessing mailboxes via API (EWS/Graph).
- **Technique**: **T1002 (Data Compressed)** - Compressing data with 7-Zip or RAR.
- **Technique**: **T1048.003 (Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol)**.
- **Simulation**:
  - Use a script to access a test mailbox via Microsoft Graph API and download emails.
  - Compress collected files into a password-protected archive.

## 🛠️ Tools Required
- **C2 Framework**: `Cobalt Strike` (or `Sliver` / `Covenant` as alternatives)
- **Recon/Auth**: `AADInternals`, `Rubeus`
- **Exploitation**: `PowerSploit`, `Impacket`
- **Malware Emulation**: `GoldFinder`, `Sibot` (custom scripts to mimic behavior)
