# Security Engineering Home Lab

## 🎯 Objective
Develop hands-on penetration testing and security engineering skills through practical cybersecurity exercises in a controlled lab environment, demonstrating both offensive and defensive security capabilities.

## 👨‍💼 About Me
Security professional with CISSP and GICSP certifications, currently working as SCA-V/ISSO, building practical security engineering skills through hands-on lab exercises. Transitioning from security assessment to hands-on security operations and engineering roles.

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
- ✅ Virtual network design and isolation
- ✅ Linux command-line administration
- ✅ Network reconnaissance and enumeration
- ✅ Vulnerability exploitation with Metasploit Framework
- ✅ Multiple attack vector exploitation (backdoors, command injection)
- ✅ Post-exploitation system enumeration
- ✅ Exploit troubleshooting and pivoting
- ✅ Service version detection and CVE correlation
- ✅ Security tool proficiency (Nmap, Metasploit)
- ✅ Professional technical documentation and reporting

## 🔍 Lab Phases

### ✅ Phase 1: Network Reconnaissance (Completed)

**Objective:** Map the attack surface of Metasploitable 2 through systematic network reconnaissance and service enumeration.

**Key Activities:**
- Verified network connectivity using ICMP ping
- Performed comprehensive port scan with Nmap
- Identified 23 open TCP ports with vulnerable services
- Correlated service versions to known CVEs

**Tools Used:** Nmap, ICMP

**Key Findings:**
- vsftpd 2.3.4 (CVE-2011-2523 - Backdoor)
- UnrealIRCD 3.2.8.1 (CVE-2010-2075 - Backdoor)
- Samba 3.0.x (CVE-2007-2447 - Command Injection)
- Unencrypted Telnet (Port 23)
- Apache 2.2.8 with known vulnerabilities
- Exposed MySQL database (Port 3306)
- Vulnerable Samba services (Ports 139/445)

**Evidence:**
![Nmap Scan Results](scans/nmap-initial-scan.png)

---

### ✅ Phase 2: Exploitation - Backdoor Attack (Completed)

**Objective:** Exploit vsftpd backdoor to gain root access and demonstrate backdoor-based attack methodology.

**Attack Summary:**
Successfully exploited the vsftpd 2.3.4 backdoor vulnerability (CVE-2011-2523) to gain root-level command execution on the target system.

**Exploitation Details:**
- **Target:** Metasploitable 2 (192.168.100.10)
- **Vulnerability:** vsftpd 2.3.4 backdoor (CVE-2011-2523)
- **Tool:** Metasploit Framework v6
- **Module:** `exploit/unix/ftp/vsftpd_234_backdoor`
- **Result:** Root shell access (UID 0)

**Attack Chain:**
1. **Reconnaissance:** Identified vsftpd 2.3.4 on port 21 (Phase 1)
2. **Weaponization:** Selected Metasploit exploit module
3. **Delivery:** Connected to FTP service, sent backdoor trigger (`:)`)
4. **Exploitation:** Backdoor activated, spawned root shell on port 6200
5. **Post-Exploitation:** Verified root access, enumerated system, accessed /etc/shadow

**Impact:** Complete system compromise with root privileges

**Evidence:**
![Root Access via vsftpd](evidence/phase2-root-access.png)

**Full Writeup:** [Phase 2 - Exploitation: vsftpd Backdoor](writeups/phase2-exploitation-vsftpd.md)

---

### ✅ Phase 3: Multiple Exploitation Attempts - Adaptability (Completed)

**Objective:** Demonstrate real-world penetration testing adaptability by attempting multiple attack vectors and pivoting when needed.

**Attack Attempts:**

**Attempt #1: UnrealIRCD Backdoor (Unsuccessful)**
- **Target:** UnrealIRCD 3.2.8.1 on port 6667
- **Vulnerability:** CVE-2010-2075 - Backdoor Command Execution
- **Payloads Tested:** 
  - `cmd/unix/reverse` - Handler binding issues
  - `cmd/unix/bind_netcat` - Connection failed
  - `cmd/unix/generic` - Session not created
- **Result:** Exploitation unsuccessful in current lab configuration
- **Decision:** Pivoted to alternative attack vector

**Attempt #2: Samba Command Injection (Successful)**
- **Target:** Samba 3.0.x on ports 139/445
- **Vulnerability:** CVE-2007-2447 - Username Map Script Command Injection
- **Tool:** Metasploit Framework v6
- **Module:** `exploit/multi/samba/usermap_script`
- **Result:** Root shell access (UID 0)

**Attack Chain:**
1. **Initial Attempt:** UnrealIRCD exploitation with multiple payload attempts
2. **Troubleshooting:** Systematic testing of different payloads and configurations
3. **Pivot Decision:** Moved to Samba after exhausting reasonable troubleshooting
4. **Successful Exploitation:** Command injection via malicious username
5. **Post-Exploitation:** Root access, system enumeration, proof of compromise

**Key Learning:** Professional penetration testing includes failed attempts, troubleshooting methodology, and strategic pivoting to alternative attack vectors.

**Evidence:**
![Root Access via Samba](evidence/phase3-samba-root-access.png)

**Full Writeup:** [Phase 3 - Multiple Exploits & Adaptability](writeups/phase3-multiple-exploits.md)

**Vulnerability Types Demonstrated:**
- **Backdoor Exploitation** (vsftpd - Phase 2)
- **Command Injection** (Samba - Phase 3)

---

### 🔄 Phase 4: Detection & Defense (In Progress)

**Objectives:**
- Deploy SIEM platform (Security Onion or ELK Stack)
- Replay Phase 2 and Phase 3 attacks while monitoring
- Detect attacks in real-time through SIEM
- Write custom detection rules (Suricata/Snort)
- Analyze attack indicators and patterns
- Implement system hardening controls
- Document blue team response procedures

**Why This Matters:**
- Demonstrates understanding of BOTH offense and defense
- SIEM experience is critical for security engineer roles
- Shows ability to think like both attacker and defender
- Completes the security engineering skillset

---

## 📈 Lab Progress

**Infrastructure & Reconnaissance:**
- [x] Lab infrastructure configured
- [x] Network segmentation implemented  
- [x] Initial reconnaissance completed (Phase 1)
- [x] Vulnerability surface mapped (23 services identified)

**Offensive Security (Red Team):**
- [x] Backdoor exploitation demonstrated (vsftpd - Phase 2)
- [x] Command injection exploitation demonstrated (Samba - Phase 3)
- [x] Root access gained via multiple attack vectors
- [x] Post-exploitation enumeration
- [x] Exploit troubleshooting and pivoting methodology
- [x] Professional attack documentation

**Defensive Security (Blue Team) - Phase 4:**
- [ ] SIEM/logging platform deployment
- [ ] Attack detection in real-time
- [ ] Detection rule development
- [ ] System hardening implementation
- [ ] Blue team response procedures

## 🎓 Learning Outcomes

This lab demonstrates practical understanding of:

**Offensive Security:**
- Attack methodologies from reconnaissance to post-exploitation
- Multiple vulnerability classes (backdoors, injection flaws)
- Systematic exploitation with Metasploit Framework
- Professional troubleshooting and pivoting strategies

**Network Security:**
- Proper network segmentation and isolation techniques
- TCP/IP protocol understanding
- Service enumeration and fingerprinting

**Vulnerability Management:**
- Systematic identification and correlation to CVEs
- Exploitation and impact assessment
- Remediation planning

**Security Engineering:**
- End-to-end attack simulation
- Tool proficiency (Nmap, Metasploit, Linux CLI)
- Defense planning and detection strategy development

**Professional Skills:**
- Comprehensive technical documentation
- Honest reporting (including failed attempts)
- Adaptability and resilience in troubleshooting
- Industry-standard penetration testing methodology

## 📝 Methodology

All exercises follow the Cyber Kill Chain and industry-standard penetration testing methodology:

1. **Reconnaissance** - Information gathering and target identification
2. **Scanning & Enumeration** - Service discovery and vulnerability mapping
3. **Exploitation** - Gaining unauthorized access through various attack vectors
4. **Post-Exploitation** - System enumeration, privilege verification, proof of compromise
5. **Detection** (Phase 4) - Identifying attack indicators and patterns
6. **Defense** (Phase 4) - Hardening and remediation
7. **Reporting** - Professional documentation with remediation guidance

Each phase is documented with:
- Clear objectives and scope
- Detailed methodology and commands with explanations
- Visual evidence (screenshots, diagrams)
- Findings with risk assessment and impact analysis
- Remediation recommendations
- Detection strategies
- Lessons learned

## 🔧 Resources

### Reference Documentation
- [Metasploit Framework Cheat Sheet](resources/metasploit-cheatsheet.md) - Quick reference for common Metasploit commands and workflows

### Lab Files Structure
```
security-homelab/
├── README.md
├── writeups/
│   ├── phase2-exploitation-vsftpd.md
│   └── phase3-multiple-exploits.md
├── evidence/
│   ├── phase2-root-access.png
│   └── phase3-samba-root-access.png
├── resources/
│   └── metasploit-cheatsheet.md
└── scans/
    └── nmap-initial-scan.png
```

## 🔐 Security & Ethics

**This laboratory environment is maintained for educational purposes and professional skill development.**

**Ethical Guidelines:**
- All activities conducted in isolated, controlled environment
- No connection to production systems or networks
- No unauthorized access to external systems
- Follows responsible disclosure and ethical hacking principles
- Complies with applicable laws and regulations

**Target System:**
- Metasploitable 2 - Intentionally vulnerable training platform
- Designed specifically for penetration testing practice
- No real data or services at risk
- Publicly available and documented as training tool

**Purpose:**
- Develop hands-on security engineering skills
- Understand both offensive and defensive security
- Prepare for security operations and engineering roles
- Build professional portfolio demonstrating practical capabilities

---

## 💼 Professional Application

**This lab demonstrates skills directly applicable to:**

**Security Engineer Roles:**
- Vulnerability assessment and penetration testing
- Security tool operation (SIEM, IDS/IPS, scanners)
- Incident detection and response
- System hardening and remediation
- Security architecture and design

**OT/ICS Security Roles:**
- Understanding of attack vectors targeting industrial systems
- Network segmentation strategies for OT environments
- Detection of anomalous activity in SCADA/ICS networks
- Risk assessment for operational technology

**Security Operations Center (SOC):**
- SIEM operation and log analysis
- Alert investigation and triage
- Threat hunting and detection rule development
- Incident response procedures

---

## 📚 References

**Tools & Frameworks:**
- **Metasploit Framework:** https://www.metasploit.com/
- **Nmap:** https://nmap.org/
- **Kali Linux:** https://www.kali.org/
- **Metasploitable:** https://sourceforge.net/projects/metasploitable/

**Standards & Methodologies:**
- **NIST Cybersecurity Framework:** https://www.nist.gov/cyberframework
- **MITRE ATT&CK:** https://attack.mitre.org/
- **OWASP Top 10:** https://owasp.org/www-project-top-ten/
- **Penetration Testing Execution Standard:** http://www.pentest-standard.org/

**Vulnerability Databases:**
- **CVE Details:** https://www.cvedetails.com/
- **Exploit Database:** https://www.exploit-db.com/
- **Rapid7 Vulnerability Database:** https://www.rapid7.com/db/

---

**Last Updated:** February 10, 2026

**Current Phase:** Detection & Defense (Phase 4 - Starting)

**Portfolio Status:** Ready for professional review with 3 completed phases demonstrating reconnaissance, multiple exploitation techniques, and professional documentation
