# Crypto24 Ransomware Adversary Simulation Plan

## 1. Executive Summary
Crypto24 is a ransomware group known for blending legitimate tools with custom malware to execute stealthy attacks. They leverage "Living off the Land" (LotL) binaries and standard Windows administrative tools to evade detection, establish persistence, and escalate privileges before deploying their ransomware payload.

This simulation plan outlines the Tactics, Techniques, and Procedures (TTPs) used by Crypto24, mapped to MITRE ATT&CK and actionable Atomic Red Team tests.

**Reference:** [Trend Micro - Crypto24 Ransomware Stealth Attacks](https://www.trendmicro.com/en_us/research/25/h/crypto24-ransomware-stealth-attacks.html)

---

## 2. Cyber Threat Intelligence (CTI) Analysis

### Key Characteristics
*   **Initial Access & Persistence**: Creation of local user accounts with generic names, added to the Administrators group. Use of Scheduled Tasks and Windows Services (`sc.exe`) for persistence.
*   **Discovery**: Extensive use of `wmic`, `net user`, and `net localgroup` via batch scripts (`1.bat`) to profile the system.
*   **Privilege Escalation**: Exploitation of the CMSTPLUA COM interface to bypass UAC. Use of `runas.exe` and `PsExec`.
*   **Defense Evasion**: Custom tools (resembling "RealBlindingEDR") to remove EDR callbacks.
*   **Lateral Movement**: Enabling multiple RDP sessions (patching `termsrv.dll`), using `PsExec`, and `TightVNC`.
*   **Collection**: Keylogging via `WinMainSvc.dll`.
*   **Impact**: Ransomware payload (`MSRuntime.dll`) executed as a service.

---

## 3. Atomic Red Team Simulation Plan

This plan is broken down by MITRE ATT&CK Tactics. You can execute these tests using the `Invoke-AtomicTest` PowerShell module.

### Phase 1: Discovery & Reconnaissance
*The adversary uses batch scripts to gather system information.*

| Technique ID | Technique Name | Atomic Test | Description |
| :--- | :--- | :--- | :--- |
| **T1082** | System Information Discovery | `T1082-1` | List System Information using `wmic` (Partition, ComputerSystem). |
| **T1087.001** | Account Discovery: Local Account | `T1087.001-1` | Enumerate local users using `net user`. |
| **T1069.001** | Permission Groups Discovery: Local Groups | `T1069.001-1` | Enumerate local groups using `net localgroup`. |

**Manual Emulation Commands (PowerShell/CMD):**
```cmd
wmic partition get name,size,type
wmic COMPUTERSYSTEM get TotalPhysicalMemory,caption
net user
net localgroup
```

### Phase 2: Persistence & Privilege Escalation
*The adversary creates backdoor accounts and malicious services.*

| Technique ID | Technique Name | Atomic Test | Description |
| :--- | :--- | :--- | :--- |
| **T1136.001** | Create Account: Local Account | `T1136.001-1` | Create a new local user account. |
| **T1098** | Account Manipulation | `T1098-1` | Add the new user to the "Administrators" group. |
| **T1543.003** | Create or Modify System Process: Windows Service | `T1543.003-1` | Create a service (mimicking `WinMainSvc` or `MSRuntime`) using `sc.exe`. |
| **T1053.005** | Scheduled Task/Job: Scheduled Task | `T1053.005-1` | Create a scheduled task to run a script. |
| **T1548.002** | Bypass UAC | `T1548.002-1` | Bypass UAC using CMSTPLUA COM interface. |

**Manual Emulation Commands:**
```cmd
:: Create User
net user crypto24_test Password123! /add
net localgroup administrators crypto24_test /add

:: Create Malicious Service (Mimic Keylogger Service)
sc create WinMainSvc type= share start= auto binPath= "C:\Windows\System32\svchost.exe -k WinMainSvc"

:: Create Ransomware Service (Mimic MSRuntime)
sc create MSRuntime type= share start= auto binpath= "C:\Windows\System32\svchost.exe -k MSRuntime" displayname= "Microsoft Runtime Manager"
```

### Phase 3: Defense Evasion
*The adversary attempts to impair defenses and evade EDR.*

| Technique ID | Technique Name | Atomic Test | Description |
| :--- | :--- | :--- | :--- |
| **T1562.001** | Impair Defenses: Disable or Modify Tools | `T1562.001-1` | Attempt to stop or disable security services (Simulated). |

### Phase 4: Lateral Movement & Collection
*The adversary prepares for lateral movement and collects credentials.*

| Technique ID | Technique Name | Atomic Test | Description |
| :--- | :--- | :--- | :--- |
| **T1021.001** | Remote Services: RDP | `T1021.001-1` | Enable RDP / Configure RDP for multiple sessions (Mimic `termsrv.dll` patch intent). |
| **T1056.001** | Input Capture: Keylogging | `T1056.001-1` | Simulate keylogging behavior (e.g., registry keys or demo scripts). |

---

## 4. Execution Guide

To run these tests using Atomic Red Team:

1.  **Install Atomic Red Team** (if not already installed):
    ```powershell
    IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing);
    Install-AtomicRedTeam -getAtomics
    ```

2.  **Run Specific Tests**:
    ```powershell
    # Discovery
    Invoke-AtomicTest T1082 -TestNumbers 1
    Invoke-AtomicTest T1087.001 -TestNumbers 1
    
    # Persistence (Cleanup is important here!)
    Invoke-AtomicTest T1136.001 -TestNumbers 1 -Cleanup
    Invoke-AtomicTest T1543.003 -TestNumbers 1 -Cleanup
    ```

## 5. Cleanup
Ensure you remove any artifacts created during the simulation:
*   Delete created users (`net user crypto24_test /delete`).
*   Delete created services (`sc delete WinMainSvc`, `sc delete MSRuntime`).
*   Remove scheduled tasks.
