# Volt Typhoon Adversary Simulation Plan

## 🚨 Threat Profile
**Volt Typhoon** (also known as **VANGUARD PANDA**, **BRONZE SILHOUETTE**) is a state-sponsored threat actor affiliated with the People's Republic of China. They are infamous for their "Living off the Land" (LOTL) techniques, targeting critical infrastructure (communications, manufacturing, utility, transportation, construction, maritime, government, information technology, and education sectors) for long-term espionage and potential disruption.

**Objective**: Stealthy persistence, pre-positioning within critical infrastructure, and espionage without using custom malware that could trigger detection.

## 🗺️ Attack Flow

### Phase 1: Initial Access
*Focus: Edge Devices and Public-Facing Applications*
- **Technique**: **T1190 (Exploit Public-Facing Application)** - Targeting Fortinet, Ivanti, Citrix, and Cisco edge devices.
- **Technique**: **T1078 (Valid Accounts)** - Using stolen credentials for VPN/RDP access.
- **Simulation**:
  - Scan for "vulnerable" edge services (simulated).
  - Attempt login to a VPN portal using a list of "compromised" credentials (valid test accounts).
  - Simulate exploitation of a web shell on an edge server (e.g., dropping a benign JSP/ASPX file).

### Phase 2: Discovery & Defense Evasion (Living off the Land)
*Focus: Native Tools and Stealth*
- **Technique**: **T1059.001 (Command and Scripting Interpreter: PowerShell)** - Using PowerShell for discovery.
- **Technique**: **T1049 (System Network Connections Discovery)** - Running `netstat`, `ipconfig`.
- **Technique**: **T1033 (System Owner/User Discovery)** - Running `whoami`, `net user`.
- **Technique**: **T1070 (Indicator Removal)** - Clearing event logs (`wevtutil cl System`).
- **Simulation**:
  - Execute a "discovery script" that only uses native binaries:
    ```cmd
    whoami
    ipconfig /all
    netstat -ano
    net user /domain
    tasklist
    ```
  - Attempt to "hide" activity by clearing specific logs (simulated by backing up logs first).

### Phase 3: Credential Access
*Focus: NTDS and LSASS*
- **Technique**: **T1003.003 (OS Credential Dumping: NTDS)** - Creating a shadow copy to extract `ntds.dit`.
- **Technique**: **T1003.001 (OS Credential Dumping: LSASS Memory)** - Dumping LSASS using `comsvcs.dll` (a LOTL technique).
- **Simulation**:
  - Run the following command to simulate LSASS dumping via native tools:
    ```cmd
    rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump <LSASS_PID> C:\temp\lsass.dmp full
    ```
  - Attempt to mount a Volume Shadow Copy using `vssadmin`.

### Phase 4: Lateral Movement & C2
*Focus: Proxying and Living off the Land*
- **Technique**: **T1090 (Proxy)** - Routing traffic through compromised SOHO routers (simulated).
- **Technique**: **T1021.001 (Remote Services: RDP)** - Moving laterally via RDP.
- **Technique**: **T1047 (Windows Management Instrumentation)** - Using `wmic` or `Invoke-WmiMethod` to execute commands on remote hosts.
- **Simulation**:
  - Use `netsh` to set up a port proxy (port forwarding) to simulate C2 routing:
    ```cmd
    netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=<TARGET_IP>
    ```
  - Execute a remote process via WMI.

## 🛠️ Tools Required
- **Discovery**: Native Windows Binaries (`net`, `ipconfig`, `whoami`, `wevtutil`)
- **Credential Access**: `vssadmin`, `comsvcs.dll`
- **Lateral Movement**: `wmic`, `PowerShell`
- **C2 Simulation**: `netsh` (for proxying), `Impacket` (for testing WMI/SMB lateral movement if native fails)
