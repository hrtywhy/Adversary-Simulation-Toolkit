# Adversary Simulation Toolkit

## 🚀 Overview
**Adversary Simulation Toolkit** is a comprehensive collection of utilities and resources designed for red teaming, adversary emulation, and security research. This repository serves as a centralized hub for tools, use cases, and documentation to facilitate realistic threat simulation.

## 🗺️ Attack Navigator
Visualize and plan your adversary emulation scenarios using the MITRE ATT&CK Navigator.
- **[MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)**: A web-based tool for annotating and exploring ATT&CK matrices. Use this to map out the TTPs for your specific simulation plans (e.g., Crypto24).

## 🛠️ Tools by Phase
This toolkit organizes tools according to the standard Red Team phases, enriched with resources from the community.

### 0. Adversary Simulation Platforms
*Automated and manual platforms for mimicking adversary behavior.*
- **[Atomic Red Team](https://www.atomicredteam.io/atomic-red-team)**: Library of simple tests mapped to the MITRE ATT&CK framework.
- **[Caldera](https://github.com/mitre/caldera)**: Automated adversary emulation system by MITRE.
- **[Infection Monkey](https://www.guardicore.com/infectionmonkey/)**: Open-source breach and attack simulation tool.
- **[OpenBAS](https://github.com/OpenBAS-Platform/openbas)**: Open Breach and Attack Simulation platform.
- **[Metta](https://github.com/uber-common/metta)**: Adversarial simulation tool by Uber (historical reference).
- **[Stratus Red Team](https://github.com/DataDog/stratus-red-team)**: "Atomic Red Team" for Cloud (AWS, Azure, GCP).

### 1. Reconnaissance
*Gathering intelligence on the target.*

**Active Intelligence Gathering**
- **[EyeWitness](https://github.com/ChrisTruncer/EyeWitness)**: Take screenshots of websites, provide server header info, and identify default credentials.
- **[AWSBucketDump](https://github.com/jordanpotti/AWSBucketDump)**: Quickly enumerate AWS S3 buckets to look for loot.
- **[AQUATONE](https://github.com/michenriksen/aquatone)**: Tools for performing reconnaissance on domain names.
- **[spoofcheck](https://github.com/BishopFox/spoofcheck)**: Checks if a domain can be spoofed from (SPF/DMARC).
- **[Nmap](https://github.com/nmap/nmap)**: Network discovery and security auditing.
- **[dnsrecon](https://github.com/darkoperator/dnsrecon)**: DNS Enumeration Script.

**Passive Intelligence Gathering**
- **[Social Mapper](https://github.com/SpiderLabs/social_mapper)**: OSINT Social Media Mapping Tool.
- **[skiptracer](https://github.com/xillwillx/skiptracer)**: OSINT scraping framework.
- **[ScrapedIn](https://github.com/dchrastil/ScrapedIn)**: Scrape LinkedIn without API restrictions.
- **[FOCA](https://github.com/ElevenPaths/FOCA)**: Find metadata and hidden information in documents.
- **[theHarvester](https://github.com/laramies/theHarvester)**: Gather emails, subdomains, hosts, employee names, open ports, and banners.
- **[Metagoofil](https://github.com/laramies/metagoofil)**: Extract metadata of public documents.
- **[SimplyEmail](https://github.com/killswitch-GUI/SimplyEmail)**: Email recon made fast and easy.
- **[truffleHog](https://github.com/dxa4481/truffleHog)**: Searches through git repositories for secrets.
- **[Just-Metadata](https://github.com/ChrisTruncer/Just-Metadata)**: Gathers and analyzes metadata about IP addresses.
- **[pwnedOrNot](https://github.com/thewhiteh4t/pwnedOrNot)**: Checks if email account has been compromised in a data breach.
- **[pwndb](https://github.com/davidtavarez/pwndb/)**: Search leaked credentials using the Onion service.

**Frameworks**
- **[Maltego](https://www.paterva.com/web7/downloads.php)**: Interactive data mining tool that renders directed graphs for link analysis.
- **[SpiderFoot](https://github.com/smicallef/spiderfoot)**: Open source footprinting and intelligence-gathering tool.
- **[datasploit](https://github.com/DataSploit/datasploit)**: OSINT Framework to perform various recon techniques.
- **[Recon-ng](https://bitbucket.org/LaNMaSteR53/recon-ng)**: Full-featured Web Reconnaissance framework.

### 2. Weaponization
*Coupling a remote access trojan with an exploit.*
- **[Composite Moniker](https://github.com/rxwx/CVE-2017-8570)**: PoC exploit for CVE-2017-8570.
- **[CACTUSTORCH](https://github.com/mdsecactivebreach/CACTUSTORCH)**: Payload Generation for Adversary Simulations.
- **[SharpShooter](https://github.com/mdsecactivebreach/SharpShooter)**: Payload creation framework for C#.
- **[Don't kill my cat (DKMC)](https://github.com/Mr-Un1k0d3r/DKMC)**: Generates obfuscated shellcode stored inside polyglot images.
- **[Malicious Macro Generator](https://github.com/Mr-Un1k0d3r/MaliciousMacroGenerator)**: Generate obfuscated macros.
- **[Invoke-Obfuscation](https://github.com/danielbohannon/Invoke-Obfuscation)**: PowerShell Obfuscator.
- **[Invoke-CradleCrafter](https://github.com/danielbohannon/Invoke-CradleCrafter)**: PowerShell remote download cradle generator.
- **[Unicorn](https://github.com/trustedsec/unicorn)**: PowerShell downgrade attack and shellcode injection.
- **[Shellter](https://www.shellterproject.com/)**: Dynamic shellcode injection tool.
- **[Veil](https://github.com/Veil-Framework/Veil)**: Generate metasploit payloads that bypass common AV.
- **[LuckyStrike](https://github.com/curi0usJack/luckystrike)**: Malicious Office macro creation.
- **[ClickOnceGenerator](https://github.com/Mr-Un1k0d3r/ClickOnceGenerator)**: Quick Malicious ClickOnceGenerator.
- **[macro_pack](https://github.com/sevagas/macro_pack)**: Automatize obfuscation and generation of MS Office documents.
- **[SocialEngineeringPayloads](https://github.com/bhdresh/SocialEngineeringPayloads)**: Collection of social engineering tricks and payloads.
- **[The Social-Engineer Toolkit](https://github.com/trustedsec/social-engineer-toolkit)**: Framework for social engineering.

### 3. Delivery
*Transmitting the weapon to the target environment.*

**Phishing**
- **[King Phisher](https://github.com/securestate/king-phisher)**: Phishing campaign toolkit.
- **[FiercePhish](https://github.com/Raikia/FiercePhish)**: Full-fledged phishing framework.
- **[Gophish](https://github.com/gophish/gophish)**: Open-source phishing toolkit.
- **[CredSniper](https://github.com/ustayready/CredSniper)**: Phishing framework supporting 2FA tokens.
- **[PwnAuth](https://github.com/fireeye/PwnAuth)**: OAuth abuse campaigns.
- **[Modlishka](https://github.com/drk1wi/Modlishka)**: Reverse proxy for ethical phishing.
- **[Evilginx](https://github.com/kgretzky/evilginx)**: Man-in-the-middle attack framework.

**Watering Hole Attack**
- **[BeEF](https://github.com/beefproject/beef)**: Browser Exploitation Framework.

### 4. Command and Control (C2)
*Establishing a command channel.*

**Remote Access Tools**
- **[Cobalt Strike](https://cobaltstrike.com/)**: Adversary Simulations and Red Team Operations software.
- **[Empire](https://github.com/EmpireProject/Empire)**: Post-exploitation framework (PowerShell/Python).
- **[Metasploit Framework](https://github.com/rapid7/metasploit-framework)**: Penetration testing framework.
- **[SILENTTRINITY](https://github.com/byt3bl33d3r/SILENTTRINITY)**: Post-exploitation agent (Python/C#/.NET).
- **[Pupy](https://github.com/n1nj4sec/pupy)**: Cross-platform remote administration tool.
- **[Koadic](https://github.com/zerosum0x0/koadic)**: Windows post-exploitation rootkit (COM C2).
- **[PoshC2](https://github.com/nettitude/PoshC2)**: Proxy aware C2 framework.
- **[Merlin](https://github.com/Ne0nd0g/merlin)**: HTTP/2 C2 server and agent (Go).
- **[Quasar](https://github.com/quasar/QuasarRAT)**: Remote administration tool (C#).
- **[Covenant](https://github.com/cobbr/Covenant)**: .NET command and control framework.
- **[FactionC2](https://github.com/FactionC2/)**: C2 framework using websockets based API.

**Staging & Infrastructure**
- **[Red Baron](https://github.com/byt3bl33d3r/Red-Baron)**: Automate creating resilient infrastructure with Terraform.
- **[EvilURL](https://github.com/UndeadSec/EvilURL)**: Generate unicode evil domains.
- **[Domain Hunter](https://github.com/threatexpress/domainhunter)**: Checks expired domains and categorization.
- **[Chameleon](https://github.com/mdsecactivebreach/Chameleon)**: Evading Proxy categorisation.
- **[Malleable C2](https://github.com/rsmudge/Malleable-C2-Profiles)**: Redefine indicators in Beacon's communication.
- **[ExternalC2](https://github.com/ryhanson/ExternalC2)**: Library for Cobalt Strike External C2.
- **[mkhtaccess_red](https://github.com/violentlydave/mkhtaccess_red)**: Auto-generate HTaccess for payload delivery.
- **[RedFile](https://github.com/outflanknl/RedFile)**: Flask app serving files with intelligence.

**Simulation C2 Frameworks**
*C2s specifically designed or well-suited for adversary simulation and research.*
- **[BEAR](https://github.com/S3N4T0R-0X0/BEAR)**: C2 framework designed for mimicking Russian APT TTPs.
- **[Sliver](https://github.com/BishopFox/sliver)**: Open source cross-platform adversary emulation/red team framework (Go).
- **[Mythic](https://github.com/its-a-feature/Mythic)**: Collaborative, multi-platform, red teaming framework.
- **[Havoc](https://github.com/HavocFramework/Havoc)**: Modern and malleable post-exploitation command and control framework.
- **[Covenant](https://github.com/cobbr/Covenant)**: .NET command and control framework (also listed above).

### 5. Lateral Movement
*Moving through the environment.*
- **[CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec)**: Swiss army knife for pentesting networks.
- **[PowerLessShell](https://github.com/Mr-Un1k0d3r/PowerLessShell)**: Execute PowerShell without spawning powershell.exe.
- **[GoFetch](https://github.com/GoFetchAD/GoFetch)**: Automatically exercise BloodHound attack plans.
- **[DeathStar](https://github.com/byt3bl33d3r/DeathStar)**: Automate gaining Domain Admin rights using Empire.
- **[Responder](https://github.com/SpiderLabs/Responder)**: LLMNR/NBT-NS/MDNS poisoner.
- **[SessionGopher](https://github.com/fireeye/SessionGopher)**: Extract saved session information.
- **[PowerSploit](https://github.com/PowerShellMafia/PowerSploit)**: Collection of PowerShell modules.
- **[Nishang](https://github.com/samratashok/nishang)**: Framework and collection of scripts/payloads.
- **[Inveigh](https://github.com/Kevin-Robertson/Inveigh)**: PowerShell LLMNR/mDNS/NBNS spoofer.
- **[Mimikatz](https://github.com/gentilkiwi/mimikatz)**: Extract credentials from memory.
- **[LaZagne](https://github.com/AlessandroZ/LaZagne)**: Retrieve passwords stored on a local computer.
- **[PsExec](https://docs.microsoft.com/en-us/sysinternals/downloads/psexec)**: Execute processes on other systems.
- **[KeeThief](https://github.com/HarmJ0y/KeeThief)**: Extraction of KeePass key material.
- **[Impacket](https://github.com/CoreSecurity/impacket)**: Python classes for network protocols.
- **[RedSnarf](https://github.com/nccgroup/redsnarf)**: Pen-testing / red-teaming tool for Windows.

### 6. Establish Foothold
*Maintaining access.*
- **[Tunna](https://github.com/SECFORCE/Tunna)**: Tunnel TCP communication over HTTP.
- **[reGeorg](https://github.com/sensepost/reGeorg)**: Create SOCKS proxies through the DMZ.
- **[Blade](https://github.com/wonderqs/Blade)**: Webshell connection tool.
- **[TinyShell](https://github.com/threatexpress/tinyshell)**: Web Shell Framework.
- **[PowerLurk](https://github.com/Sw4mpf0x/PowerLurk)**: Malicious WMI Event Subscriptions.
- **[DAMP](https://github.com/HarmJ0y/DAMP)**: Persistence through Host-based Security Descriptor Modification.

### 7. Escalate Privileges
*Gaining higher-level permissions.*

**Domain Escalation**
- **[PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1)**: Network situational awareness on Windows domains.
- **[Get-GPPPassword](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-GPPPassword.ps1)**: Retrieve plaintext password from Group Policy.
- **[Invoke-ACLpwn](https://github.com/fox-it/Invoke-ACLPwn)**: Automate discovery and pwnage of ACLs.
- **[BloodHound](https://github.com/BloodHoundAD/BloodHound)**: Reveal hidden relationships in AD.
- **[PyKEK](https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS14-068/pykek)**: Python Kerberos Exploitation Kit.
- **[Grouper](https://github.com/l0ss/Grouper)**: Find vulnerable settings in AD Group Policy.
- **[ADRecon](https://github.com/sense-of-security/ADRecon)**: Extract artifacts from AD.
- **[ACLight](https://github.com/cyberark/ACLight)**: Discovery of Domain Privileged Accounts.
- **[LAPSToolkit](https://github.com/leoloobeek/LAPSToolkit)**: Audit and attack LAPS environments.
- **[PingCastle](https://www.pingcastle.com/download)**: Audit risk level of AD infrastructure.
- **[RiskySPNs](https://github.com/cyberark/RiskySPN)**: Detect and abuse accounts associated with SPNs.
- **[Rubeus](https://github.com/GhostPack/Rubeus)**: C# toolset for raw Kerberos interaction.
- **[kekeo](https://github.com/gentilkiwi/kekeo)**: Manipulate Microsoft Kerberos in C.

**Local Escalation**
- **[UACMe](https://github.com/hfiref0x/UACME)**: Bypass Windows User Account Control.
- **[windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)**: Collection of Windows kernel exploits.
- **[PowerUp](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1)**: Common Windows privilege escalation vectors.
- **[The Elevate Kit](https://github.com/rsmudge/ElevateKit)**: Privilege escalation with Cobalt Strike.
- **[Sherlock](https://github.com/rasta-mouse/Sherlock)**: Find missing software patches.
- **[Tokenvator](https://github.com/0xbadjuju/Tokenvator)**: Elevate privilege with Windows Tokens.

### 8. Data Exfiltration
*Stealing data.*
- **[CloakifyFactory](https://github.com/TryCatchHCF/Cloakify)**: Data Exfiltration & Infiltration In Plain Sight.
- **[DET](https://github.com/sensepost/DET)**: Data Exfiltration Toolkit.
- **[DNSExfiltrator](https://github.com/Arno0x/DNSExfiltrator)**: Exfiltrate data over DNS.
- **[PyExfil](https://github.com/ytisf/PyExfil)**: Python Package for Data Exfiltration.
- **[Egress-Assess](https://github.com/ChrisTruncer/Egress-Assess)**: Test egress data detection capabilities.
- **[Powershell RAT](https://github.com/Viralmaniar/Powershell-RAT)**: Exfiltrate data as email attachment.

### 9. Misc
*Other useful tools.*

**Wireless Networks**
- **[Wifiphisher](https://github.com/wifiphisher/wifiphisher)**: Automated phishing attacks against Wi-Fi networks.
- **[Evilginx](https://github.com/kgretzky/evilginx)**: Man-in-the-middle attack framework.
- **[mana](https://github.com/sensepost/mana)**: Toolkit for wifi rogue AP attacks.

**Embedded & Peripheral Devices**
- **[magspoof](https://github.com/samyk/magspoof)**: Spoof/emulate magnetic stripes.
- **[P4wnP1](https://github.com/mame82/P4wnP1)**: Highly customizable USB attack platform.
- **[poisontap](https://github.com/samyk/poisontap)**: Exploits locked computers over USB.
- **[WHID](https://github.com/whid-injector/WHID)**: WiFi HID Injector.

**Team Communication**
- **[RocketChat](https://rocket.chat)**: Open source team chat.
- **[Etherpad](https://etherpad.net)**: Collaborative real-time editor.

**Log Aggregation**
- **[RedELK](https://github.com/outflanknl/RedELK/)**: Red Team's SIEM.
- **[CobaltSplunk](https://github.com/vysec/CobaltSplunk)**: Splunk Dashboard for CobaltStrike logs.

**C# Offensive Framework**
- **[SharpSploit](https://github.com/cobbr/SharpSploit)**: .NET post-exploitation library.
- **[GhostPack](https://github.com/GhostPack)**: Collection of C# implementations (Seatbelt, SharpUp, etc.).
- **[SharpWeb](https://github.com/djhohnstein/SharpWeb)**: Retrieve saved browser credentials.

**Labs**
- **[Detection Lab](https://github.com/clong/DetectionLab)**: Quickly build a Windows domain with security tooling.
- **[Invoke-ADLabDeployer](https://github.com/outflanknl/Invoke-ADLabDeployer)**: Automated deployment of Windows and AD test labs.

**Scripts**
- **[Aggressor Scripts](https://github.com/bluscreenofjeff/AggressorScripts)**: Scripts for Cobalt Strike.
- **[PowerShell-Suite](https://github.com/FuzzySecurity/PowerShell-Suite)**: Collection of PowerShell scripts.

---

## 📂 Local Tools Directory
The `Tools` directory in this repository contains essential binaries and scripts for quick access:
- **Remote Access & Administration**: `AnyDesk`, `Advanced IP Scanner`
- **Network Discovery**: `IP Scan`
- **Privilege Escalation**: `winPEAS` (and more)

## 🗂️ Resources
Templates and guides for planning and executing adversary emulations.
- **[Adversary Emulation Plan Template](Resources/Adversary%20Emulation/Adversary%20Emulation%20Plan%20Template.xlsx)**: Excel template for planning scenarios.
- **[APT3 Adversary Emulation Field Manual](Resources/Adversary%20Emulation/APT3_Adversary_Emulation_Field_Manual%202.xlsx)**: Detailed field manual for APT3 emulation.
- **[Cobalt Strike Cheat Sheet](Resources/Adversary%20Emulation/Cobalt%20Strike%20-%20Cheat%20Sheet.md)**: Quick reference for Cobalt Strike commands.
- **[Ransomware Overview](Resources/Adversary%20Emulation/Ransomware%20Overview.xlsx)**: Comprehensive overview of ransomware families.

## 📚 Use Cases
Explore the `Use Case` directory for detailed simulation plans and scenarios.

**Ransomware & Cybercrime**
- **[Crypto24 Adversary Simulation Plan](Use%20Case/Crypto24_Adversary_Simulation_Plan.md)**: A deep dive into mimicking the TTPs of the Crypto24 ransomware group.
- **[SLSH (Scattered LAPSUS$ Hunters) Plan](Use%20Case/SLSH_Adversary_Simulation_Plan.md)**: Simulation of the federated cybercriminal alliance merging Scattered Spider, LAPSUS$, and ShinyHunters.

**State-Sponsored APTs**
*Comprehensive simulation plans for major nation-state actors.*
- **[Russian APTs](Use%20Case/Russian%20APT)**: Includes **APT29 (Cozy Bear)**, **APT28 (Fancy Bear)**, and others.
- **[Chinese APTs](Use%20Case/Chinese%20APT)**: Includes **Mustang Panda**, **Wicked Panda**, and others.
- **[North Korean APTs](Use%20Case/North%20Koreans%20APT)**: Includes **Labyrinth Chollima**, **Velvet Chollima**, and others.
- **[Iranian APTs](Use%20Case/Iranian%20APT)**: Includes **Helix Kitten**, **Pioneer Kitten**, and others.

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
