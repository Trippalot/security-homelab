# Security Engineering Home Lab

## 🎯 Objective
Develop comprehensive hands-on penetration testing and security engineering skills through practical cybersecurity exercises in a controlled lab environment, demonstrating both offensive (red team) and defensive (blue team) security capabilities.

## 👨‍💼 About Me
Security professional with CISSP and GICSP certifications, currently working as SCA-V/ISSO. Building practical security engineering skills through hands-on lab exercises to transition from security assessment to hands-on security operations and engineering roles. This lab demonstrates end-to-end security capabilities from reconnaissance through exploitation to detection and defense.

## 🏗️ Lab Architecture

### Infrastructure
- **Hypervisor:** VMware Workstation Pro
- **Host System:** Windows 11 (Lenovo Yoga 730-15IKB, 8GB RAM, i5-8250U)
- **Network Segmentation:** Isolated virtual network (192.168.100.0/24)

### Virtual Machines

| Machine | Role | Operating System | IP Address | Resources |
|---------|------|------------------|------------|-----------|
| Kali Linux 2024.x | Attack Platform | Debian-based | 192.168.100.5 | 2.5GB RAM, 2 cores |
| Metasploitable 2 | Vulnerable Target | Ubuntu 8.04 | 192.168.100.10 | 512MB RAM, 1 core |

### Network Design
```
                    [Windows 11 Host]
                     8GB RAM | i5-8250U
                            |
                    [VMware Workstation Pro]
                            |
        +-------------------+-------------------+
        |                                       |
  [NAT Network]                        [VMnet2: 192.168.100.0/24]
  (Internet Access)                      (Isolated Attack Network)
        |                                       |
    +-------+-------+                   +-------+-------+
    |               |                   |               |
[Kali Linux]  [Metasploitable]     [Kali Linux]  [Metasploitable]
  eth0           eth0                 eth1           eth1
                                    (Attacker)       (Target)
```

## 📊 Skills Demonstrated

### Offensive Security (Red Team)
- ✅ Network reconnaissance and enumeration
- ✅ Vulnerability identification and assessment
- ✅ Exploitation with Metasploit Framework
- ✅ Multiple attack vector execution (backdoors, command injection)
- ✅ Post-exploitation system enumeration
- ✅ Privilege escalation techniques
- ✅ Attack documentation and reporting

### Defensive Security (Blue Team)
- ✅ Intrusion detection system deployment (Suricata)
- ✅ Security monitoring and alert analysis
- ✅ Attack pattern recognition
- ✅ Log analysis and correlation
- ✅ Detection rule management
- ✅ Incident investigation methodology

### Technical Proficiency
- ✅ Linux command-line administration
- ✅ Virtual network design and isolation
- ✅ Security tool configuration and operation
- ✅ Service version detection and CVE correlation
- ✅ Professional technical documentation
- ✅ SIEM architecture understanding

## 🔍 Lab Phases

### ✅ Phase 1: Network Reconnaissance

**Objective:** Map the attack surface of Metasploitable 2 through systematic network reconnaissance and service enumeration.

**Key Activities:**
- Verified network connectivity using ICMP ping
- Performed comprehensive port scan with Nmap
- Identified 23 open TCP ports with vulnerable services
- Correlated service versions to known CVEs
- Documented findings for exploitation planning

**Tools Used:** Nmap, ICMP

**Key Findings:**
- vsftpd 2.3.4 (CVE-2011-2523 - Backdoor)
- UnrealIRCD 3.2.8.1 (CVE-2010-2075 - Backdoor)
- Samba 3.0.x (CVE-2007-2447 - Command Injection)
- Unencrypted Telnet (Port 23)
- Apache 2.2.8 with known vulnerabilities
- Exposed MySQL database (Port 3306)
- Vulnerable Samba services (Ports 139/445)

**Skills Demonstrated:**
- Network scanning and enumeration
- Service fingerprinting
- Vulnerability correlation
- Attack surface mapping

**Evidence:**
![Nmap Scan Results](scans/nmap-initial-scan.png)

**Full Writeup:** [Phase 1 - Reconnaissance](writeups/phase1-reconnaissance.md) *(to be uploaded)*

---

### ✅ Phase 2: Exploitation - Backdoor Attack

**Objective:** Exploit vsftpd backdoor to gain root access and demonstrate backdoor-based attack methodology.

**Attack Summary:**
Successfully exploited the vsftpd 2.3.4 backdoor vulnerability (CVE-2011-2523) to gain root-level command execution on the target system through systematic exploitation using Metasploit Framework.

**Exploitation Details:**
- **Target:** Metasploitable 2 (192.168.100.10)
- **Vulnerability:** vsftpd 2.3.4 backdoor (CVE-2011-2523)
- **Tool:** Metasploit Framework v6
- **Module:** `exploit/unix/ftp/vsftpd_234_backdoor`
- **Result:** Root shell access (UID 0)

**Attack Chain:**
1. **Reconnaissance:** Identified vsftpd 2.3.4 on port 21 via Nmap (Phase 1)
2. **Weaponization:** Selected appropriate Metasploit exploit module
3. **Delivery:** Connected to FTP service, sent backdoor trigger (`:)` in username)
4. **Exploitation:** Backdoor activated, spawned root shell on port 6200
5. **Post-Exploitation:** Verified root access, enumerated system, accessed /etc/shadow

**Technical Details:**
- Backdoor mechanism: Malicious code in vsftpd source
- Trigger: Username containing `:)` smiley face
- Backdoor port: 6200 (opened after trigger)
- Access level: Root (UID 0, GID 0)

**Impact:** Complete system compromise with highest privilege level

**Skills Demonstrated:**
- Metasploit Framework proficiency
- Backdoor exploitation techniques
- Post-exploitation enumeration
- Root-level system access
- Professional documentation

**Evidence:**
![Root Access via vsftpd](evidence/phase2-root-access.png)

**Full Writeup:** [Phase 2 - Exploitation: vsftpd Backdoor](writeups/phase2-exploitation-vsftpd.md)

---

### ✅ Phase 3: Multiple Exploitation Attempts - Adaptability

**Objective:** Demonstrate real-world penetration testing adaptability by attempting multiple attack vectors, troubleshooting failures, and successfully pivoting when initial attempts don't succeed.

**Attack Attempts:**

#### Attempt #1: UnrealIRCD Backdoor (Unsuccessful)
- **Target:** UnrealIRCD 3.2.8.1 on port 6667
- **Vulnerability:** CVE-2010-2075 - Backdoor Command Execution
- **Module:** `exploit/unix/irc/unreal_ircd_3281_backdoor`
- **Payloads Tested:** 
  - `cmd/unix/reverse` - Handler binding issues
  - `cmd/unix/bind_netcat` - Connection failed
  - `cmd/unix/generic` - Session not created
- **Troubleshooting:** Systematic payload selection, configuration adjustment, network verification
- **Result:** Exploitation unsuccessful in current lab configuration
- **Decision:** Professional pivot to alternative attack vector

#### Attempt #2: Samba Command Injection (Successful)
- **Target:** Samba 3.0.x on ports 139/445
- **Vulnerability:** CVE-2007-2447 - Username Map Script Command Injection
- **Tool:** Metasploit Framework v6
- **Module:** `exploit/multi/samba/usermap_script`
- **Result:** Root shell access (UID 0)

**Attack Chain:**
1. **Initial Attempt:** UnrealIRCD exploitation with multiple payload configurations
2. **Troubleshooting:** Systematic testing of different payloads and network settings
3. **Pivot Decision:** Moved to Samba exploitation after exhausting reasonable troubleshooting
4. **Successful Exploitation:** Command injection via malicious username containing shell metacharacters
5. **Post-Exploitation:** Root access verified, system enumeration, proof of compromise

**Technical Details:**
- **Samba vulnerability:** Improper input sanitization in username map script feature
- **Exploit mechanism:** Shell metacharacters in username field (backticks for command execution)
- **Access level:** Root (UID 0, GID 0)
- **Ports:** 139 (NetBIOS), 445 (Direct SMB)

**Key Learning:** Professional penetration testing includes failed attempts, systematic troubleshooting methodology, and strategic pivoting to alternative attack vectors when appropriate.

**Skills Demonstrated:**
- Multiple vulnerability class exploitation
- Systematic troubleshooting methodology
- Professional pivoting and adaptability
- Command injection techniques
- Honest documentation (including failures)
- Real-world penetration testing experience

**Evidence:**
![Root Access via Samba](evidence/phase3-samba-root-access.png)

**Vulnerability Types Demonstrated:**
- **Backdoor Exploitation** (vsftpd - Phase 2): Supply chain attack, malicious code insertion
- **Command Injection** (Samba - Phase 3): Input validation failure, shell metacharacter abuse

**Full Writeup:** [Phase 3 - Multiple Exploits & Adaptability](writeups/phase3-multiple-exploits.md)

---

### ✅ Phase 4: Intrusion Detection & Defense

**Objective:** Deploy network-based intrusion detection to detect and analyze attack attempts, demonstrating blue team capabilities and complete security engineering lifecycle understanding.

**Approach Summary:**

#### Initial Attempt: Security Onion SIEM
- Attempted enterprise SIEM deployment (Security Onion 2.3.300)
- Completed full installation wizard configuration
- Encountered resource constraints (Elasticsearch requires 12GB+ RAM)
- Installation stalled at 73-78% (Elasticsearch initialization)
- **Learning Outcome:** SIEM capacity planning, architecture understanding, professional troubleshooting

#### Implemented Solution: Suricata IDS
- Deployed lightweight Suricata IDS (industry-standard detection engine)
- Configured network monitoring on isolated attack network
- Updated Emerging Threats rulesets (6,457 signatures)
- Successfully detected all Phase 2 and Phase 3 attacks in real-time

**Detection Results:**

**✅ Detection #1: vsftpd Backdoor (CVE-2011-2523)**
```
[1:2100498:7] GPL ATTACK_RESPONSE id check returned root
Classification: Potentially Bad Traffic | Priority: 2
Port 6200 (backdoor) | Detection: Signature-based
```
- Detected root access indicator in backdoor traffic
- Real-time alert generation (< 1 second latency)
- Matched string "uid=0(root)" in network traffic

**✅ Detection #2: Samba Command Injection (CVE-2007-2447)**
```
[1:2210016:2] SURICATA STREAM CLOSEWAIT FIN out of window
Classification: Generic Protocol Command Decode | Priority: 3
Port 139 (Samba) | Detection: Behavioral anomaly
```
- Detected abnormal TCP connection behavior during exploitation
- Behavioral detection (not signature-specific)
- Protocol-level anomaly identification

**Technical Implementation:**
- **IDS Engine:** Suricata 8.0.3
- **Ruleset:** Emerging Threats Open (ETOPEN)
- **Monitoring Interface:** eth1 (isolated attack network)
- **Home Network:** 192.168.100.0/24
- **Log Files:** fast.log (alerts), eve.json (detailed events)

**Detection Methods Demonstrated:**
- Signature-based detection (known attack patterns)
- Behavioral anomaly detection (unusual network activity)
- Real-time monitoring and alerting
- Log analysis and correlation

**Skills Demonstrated:**
- IDS deployment and configuration
- Rule management (suricata-update)
- Alert analysis and interpretation
- Network traffic monitoring
- Command-line log analysis
- Understanding of signature vs. behavioral detection
- SIEM architecture knowledge (from Security Onion attempts)
- Professional problem-solving and pivoting
- Blue team operations

**Why Lightweight Approach Provided Better Learning:**
- Direct interaction with configuration files
- Manual rule management
- Raw log analysis (not GUI abstraction)
- Command-line proficiency development
- Deeper understanding of detection mechanisms
- More transferable skills across platforms

**Evidence:**
![Suricata Alert Detection](evidence/phase4-suricata-alerts.png)

**Full Writeup:** [Phase 4 - Intrusion Detection & Defense](writeups/phase4-intrusion-detection.md)

---

## 📈 Complete Lab Progress

### Infrastructure & Setup
- [x] Lab infrastructure configured with isolated network
- [x] Virtual machines deployed and networked
- [x] Attack and target systems operational
- [x] Network segmentation implemented

### Offensive Security (Red Team) - Complete
- [x] **Phase 1:** Network reconnaissance and vulnerability identification
- [x] **Phase 2:** Initial exploitation (vsftpd backdoor - CVE-2011-2523)
- [x] **Phase 3:** Additional exploitation (Samba command injection - CVE-2007-2447)
- [x] Multiple attack vector demonstration
- [x] Root access achieved via multiple methods
- [x] Post-exploitation system enumeration
- [x] Professional attack documentation

### Defensive Security (Blue Team) - Complete
- [x] **Phase 4:** Intrusion detection system deployment
- [x] Attack detection in real-time
- [x] Alert analysis and correlation
- [x] Both signature and behavioral detection demonstrated
- [x] Professional defensive documentation

### Professional Development
- [x] GitHub portfolio created with comprehensive documentation
- [x] Resume updated with hands-on security engineering experience
- [x] Interview preparation materials developed
- [x] Both offensive and defensive capabilities demonstrated

---

## 🎓 Learning Outcomes

This lab demonstrates practical understanding of:

### Offensive Security (Red Team)
- Complete attack lifecycle from reconnaissance to post-exploitation
- Multiple vulnerability classes (backdoors, command injection)
- Systematic exploitation with Metasploit Framework
- Professional troubleshooting and pivoting strategies
- Real-world penetration testing methodology

### Defensive Security (Blue Team)
- Intrusion detection system deployment and operation
- Security monitoring and alert analysis
- Attack pattern recognition and correlation
- Understanding of detection methods (signature vs. behavioral)
- SIEM architecture and capacity planning

### Network Security
- Proper network segmentation and isolation techniques
- TCP/IP protocol understanding
- Service enumeration and fingerprinting
- Network traffic analysis
- Packet-level security analysis

### System Administration
- Linux command-line proficiency
- Service configuration and management
- Log file navigation and analysis
- Virtual machine administration
- Network interface configuration

### Vulnerability Management
- Systematic vulnerability identification
- CVE correlation and research
- Exploitation validation
- Impact assessment
- Remediation planning

### Security Engineering
- End-to-end attack simulation and detection
- Tool proficiency (Nmap, Metasploit, Suricata)
- Defense planning and detection strategy development
- Professional documentation and reporting
- Resource planning and constraint management

### Professional Skills
- Comprehensive technical documentation
- Honest reporting (including failed attempts and lessons learned)
- Adaptability and resilience in troubleshooting
- Industry-standard penetration testing methodology
- Strategic thinking and decision-making

---

## 📝 Methodology

All exercises follow the Cyber Kill Chain and industry-standard penetration testing methodology:

### Attack Lifecycle
1. **Reconnaissance** - Information gathering and target identification
2. **Scanning & Enumeration** - Service discovery and vulnerability mapping
3. **Exploitation** - Gaining unauthorized access through various attack vectors
4. **Post-Exploitation** - System enumeration, privilege verification, proof of compromise
5. **Documentation** - Professional reporting with remediation guidance

### Detection Lifecycle
1. **Deployment** - IDS sensor installation and configuration
2. **Monitoring** - Real-time traffic analysis and alert generation
3. **Detection** - Identifying attack indicators and patterns
4. **Analysis** - Alert triage, correlation, and investigation
5. **Documentation** - Detection strategy and findings reporting

### Documentation Standards
Each phase includes:
- Clear objectives and scope definition
- Detailed methodology with command explanations
- Visual evidence (screenshots, network diagrams)
- Findings with risk assessment and impact analysis
- Remediation recommendations
- Detection strategies and indicators of compromise
- Lessons learned and future improvements

---

## 🔧 Resources

### Documentation
- [Metasploit Framework Cheat Sheet](resources/metasploit-cheatsheet.md) - Quick reference for common Metasploit commands and workflows
- Phase writeups with detailed technical explanations (see Lab Phases section)

### Lab Files Structure
```
security-homelab/
├── README.md                              # This file
├── writeups/
│   ├── phase1-reconnaissance.md           # (To be uploaded)
│   ├── phase2-exploitation-vsftpd.md      # vsftpd backdoor exploitation
│   ├── phase3-multiple-exploits.md        # Samba exploitation + UnrealIRCD attempts
│   └── phase4-intrusion-detection.md      # Suricata IDS deployment + Security Onion attempts
├── evidence/
│   ├── phase2-root-access.png             # vsftpd exploitation proof
│   ├── phase3-samba-root-access.png       # Samba exploitation proof
│   └── phase4-suricata-alerts.png         # Real-time attack detection
├── resources/
│   └── metasploit-cheatsheet.md           # Metasploit reference guide
└── scans/
    └── nmap-initial-scan.png              # Network reconnaissance results
```

---

## 🔐 Security & Ethics

**This laboratory environment is maintained for educational purposes and professional skill development.**

### Ethical Guidelines
- All activities conducted in isolated, controlled environment
- No connection to production systems or networks
- No unauthorized access to external systems
- Follows responsible disclosure and ethical hacking principles
- Complies with applicable laws and regulations

### Target System
- **Metasploitable 2:** Intentionally vulnerable training platform
- Designed specifically for penetration testing practice
- No real data or services at risk
- Publicly available and documented as training tool
- Maintained by Rapid7 for security education

### Purpose & Scope
- Develop hands-on security engineering skills
- Understand both offensive and defensive security
- Prepare for security operations and engineering roles
- Build professional portfolio demonstrating practical capabilities
- Learn real-world attack and defense techniques in safe environment

### Legal Compliance
- All activities authorized (self-owned lab)
- No computer fraud or abuse violations
- No unauthorized access attempts
- Educational use only
- Professional development purposes

---

## 💼 Professional Application

**This lab demonstrates skills directly applicable to:**

### Security Engineer Roles
- Vulnerability assessment and penetration testing
- Security tool operation (SIEM, IDS/IPS, scanners)
- Incident detection and response
- System hardening and remediation
- Security architecture and design
- Attack pattern recognition
- Log analysis and correlation

### OT/ICS Security Roles
- Understanding of attack vectors targeting industrial systems
- Network segmentation strategies for OT environments
- Detection of anomalous activity in SCADA/ICS networks
- Risk assessment for operational technology
- Security monitoring without operational disruption
- Critical infrastructure protection

### Security Operations Center (SOC)
- SIEM operation and log analysis
- Alert investigation and triage
- Threat hunting and detection rule development
- Incident response procedures
- Attack correlation and pattern recognition
- Real-time security monitoring

### Penetration Testing
- Systematic vulnerability identification
- Exploitation technique execution
- Post-exploitation enumeration
- Professional reporting and documentation
- Attack chain development
- Multiple attack vector utilization

---

## 📚 References

### Tools & Frameworks
- **Metasploit Framework:** https://www.metasploit.com/
- **Nmap:** https://nmap.org/
- **Suricata:** https://suricata.io/
- **Kali Linux:** https://www.kali.org/
- **Metasploitable:** https://sourceforge.net/projects/metasploitable/
- **Security Onion:** https://securityonionsolutions.com/

### Standards & Methodologies
- **NIST Cybersecurity Framework:** https://www.nist.gov/cyberframework
- **MITRE ATT&CK:** https://attack.mitre.org/
- **OWASP Top 10:** https://owasp.org/www-project-top-ten/
- **Penetration Testing Execution Standard:** http://www.pentest-standard.org/
- **Cyber Kill Chain:** https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html

### Vulnerability Databases
- **CVE Details:** https://www.cvedetails.com/
- **Exploit Database:** https://www.exploit-db.com/
- **Rapid7 Vulnerability Database:** https://www.rapid7.com/db/
- **National Vulnerability Database:** https://nvd.nist.gov/

### Detection & Defense
- **Emerging Threats Rules:** https://rules.emergingthreats.net/
- **Suricata Documentation:** https://docs.suricata.io/
- **Security Onion Documentation:** https://docs.securityonion.net/

---

## 🚀 Future Enhancements

### Planned Improvements

**Short-Term (Next 1-2 Weeks):**
- Custom Suricata rule development for lab-specific attacks
- Packet-level analysis with Wireshark/tcpdump
- Additional vulnerability exploitation (web applications, databases)
- Automated attack replay scripting

**Medium-Term (Next 1-2 Months):**
- Web application security (DVWA, bWAPP)
- Password cracking and hash analysis
- Active Directory attack simulation
- Privilege escalation techniques
- Python automation scripts for reconnaissance and exploitation

**Long-Term (Future Projects):**
- Security Onion deployment (cloud-based with adequate resources)
- Full SIEM integration with log correlation
- Custom detection rule library development
- Threat intelligence integration
- Red team vs. Blue team exercises
- Container security (Docker/Kubernetes)
- Cloud security (AWS/Azure penetration testing)

### Continuous Learning Path
- Advanced exploit development
- Reverse engineering and malware analysis
- Wireless security assessment
- Mobile application security
- API security testing
- Social engineering simulations

---

## 📊 Project Statistics

**Time Investment:**
- Phase 1 (Reconnaissance): ~2 hours
- Phase 2 (Exploitation): ~3 hours
- Phase 3 (Multiple Exploits): ~4 hours
- Phase 4 (Detection): ~6 hours (including Security Onion attempts)
- Documentation: ~4 hours
- **Total:** ~19 hours of hands-on security engineering work

**Vulnerabilities:**
- Identified: 23 vulnerable services
- Exploited: 2 (vsftpd, Samba)
- Detected: 2 (both exploits detected by IDS)

**Skills Gained:**
- 10+ security tools and frameworks
- 20+ command-line utilities
- 2 programming/scripting languages (Bash, basic Python)
- Industry-standard methodologies and frameworks

**Documentation:**
- 4 comprehensive phase writeups
- 1 tool reference guide
- Multiple evidence artifacts
- Professional portfolio-ready materials

---

**Last Updated:** February 12, 2026

**Current Status:** All 4 phases complete - Full security engineering lifecycle demonstrated (Reconnaissance → Exploitation → Detection → Defense)

**Portfolio Status:** Interview-ready with comprehensive documentation demonstrating both offensive and defensive security capabilities

---

**Repository:** https://github.com/Trippalot/security-homelab

**Author:** Jordan (Trippalot)

**Certifications:** CISSP, GICSP

**Purpose:** Professional development and security engineering skill demonstration
