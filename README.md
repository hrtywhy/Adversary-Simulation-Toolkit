## 🚀 Overview
**Adversary Simulation Toolkit** is a comprehensive collection of utilities and resources designed for red teaming, adversary emulation, and security research. This repository serves as a centralized hub for tools, use cases, and documentation to facilitate realistic threat simulation.

## �️ Attack Navigator
Visualize and plan your adversary emulation scenarios using the MITRE ATT&CK Navigator.
- **[MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)**: A web-based tool for annotating and exploring ATT&CK matrices. Use this to map out the TTPs for your specific simulation plans (e.g., Crypto24).

## �🛠️ Tools by Phase
This toolkit organizes tools according to the standard Red Team phases.

### 1. Reconnaissance
*Gathering intelligence on the target.*
- **[EyeWitness](https://github.com/ChrisTruncer/EyeWitness)**: Take screenshots of websites, provide server header info, and identify default credentials.
- **[theHarvester](https://github.com/laramies/theHarvester)**: Gather emails, subdomains, hosts, employee names, open ports, and banners.
- **[Nmap](https://github.com/nmap/nmap)**: Network discovery and security auditing.
- **[BloodHound](https://github.com/BloodHoundAD/BloodHound)**: Reveal hidden relationships within an Active Directory environment.

### 2. Weaponization
*Coupling a remote access trojan with an exploit.*
- **[LuckyStrike](https://github.com/curi0usJack/luckystrike)**: PowerShell based utility for the creation of malicious Office macro documents.
- **[Veil](https://github.com/Veil-Framework/Veil)**: Generate metasploit payloads that bypass common anti-virus solutions.
- **[Invoke-Obfuscation](https://github.com/danielbohannon/Invoke-Obfuscation)**: PowerShell Obfuscator.

### 3. Delivery
*Transmitting the weapon to the target environment.*
- **[Gophish](https://github.com/gophish/gophish)**: Open-source phishing toolkit.
- **[King Phisher](https://github.com/securestate/king-phisher)**: Tool for testing and promoting user awareness by simulating real world phishing attacks.
- **[Evilginx](https://github.com/kgretzky/evilginx)**: Man-in-the-middle attack framework used for phishing credentials and session cookies.

### 4. Exploitation & Installation
*Exploiting vulnerabilities to execute code and install a backdoor.*
- **[Metasploit Framework](https://github.com/rapid7/metasploit-framework)**: Penetration testing framework.
- **[Cobalt Strike](https://cobaltstrike.com/)**: Software for Adversary Simulations and Red Team Operations.
- **[Empire](https://github.com/EmpireProject/Empire)**: Post-exploitation framework.
- **[Impacket](https://github.com/CoreSecurity/impacket)**: Collection of Python classes for working with network protocols.

### 5. Command and Control (C2)
*Establishing a command channel.*
- **[Covenant](https://github.com/cobbr/Covenant)**: .NET command and control framework.
- **[Merlin](https://github.com/Ne0nd0g/merlin)**: Cross-platform post-exploitation HTTP/2 Command & Control server and agent.
- **[PoshC2](https://github.com/nettitude/PoshC2)**: Proxy aware C2 framework written completely in PowerShell.

### 6. Actions on Objectives
*Achieving the original goals (Data Exfiltration, Lateral Movement, etc.).*
- **[Mimikatz](https://github.com/gentilkiwi/mimikatz)**: Extract plaintexts passwords, hash, PIN code and kerberos tickets from memory.
- **[CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec)**: Swiss army knife for pentesting networks.
- **[PowerSploit](https://github.com/PowerShellMafia/PowerSploit)**: Collection of Microsoft PowerShell modules for penetration testers.
- **[Rubeus](https://github.com/GhostPack/Rubeus)**: C# toolset for raw Kerberos interaction and abuses.

---

## 📂 Local Tools Directory
The `Tools` directory in this repository contains essential binaries and scripts for quick access:
- **Remote Access & Administration**: `AnyDesk`, `Advanced IP Scanner`
- **Network Discovery**: `IP Scan`
- **Privilege Escalation**: `winPEAS` (and more)

## 📚 Use Cases
Explore the `Use Case` directory for detailed simulation plans and scenarios, including:
- **Crypto24 Adversary Simulation Plan**: A deep dive into mimicking the TTPs of the Crypto24 ransomware group.

## 📦 Installation & Usage
1. Clone the repository:
   ```bash
   git clone https://github.com/hrtywhy/host-tools.git
   ```
2. Navigate to the directory:
   ```bash
   cd host-tools
   ```
3. Explore the `Tools` and `Use Case` directories for specific resources.

## 🤝 Contribution
Contributions are welcome! Please submit a pull request or open an issue to suggest new tools or simulation scenarios.

## ⚠️ Disclaimer
This toolkit is intended for **educational and authorized security testing purposes only**. The authors are not responsible for any misuse of these tools. Always obtain proper authorization before conducting any security assessments.
