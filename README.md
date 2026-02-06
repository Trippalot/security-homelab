# Security Engineering Home Lab

## 🎯 Objective
Develop hands-on penetration testing and security engineering skills through practical cybersecurity exercises in a controlled lab environment.

## 👨‍💼 About Me
Security professional with CISSP and GICSP certifications, currently working as SCA-V/ISSO, building practical security engineering skills through hands-on lab exercises.

## 🏗️ Lab Architecture

### Infrastructure
- **Hypervisor:** VMware Workstation Pro
- **Host System:** Windows 11 (Lenovo Yoga 730-15IKB)
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
- ✅ Post-exploitation system enumeration
- ✅ Service version detection and CVE correlation
- ✅ Security tool proficiency (Nmap, Metasploit)
- ✅ Technical documentation and professional reporting

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
- Unencrypted Telnet (Port 23)
- Apache 2.2.8 with known vulnerabilities
- Exposed MySQL database (Port 3306)
- Vulnerable Samba services (Ports 139/445)

**Documentation:** [Phase 1 Details in README](https://github.com/Trippalot/security-homelab)

---

### ✅ Phase 2: Exploitation (Completed)

**Objective:** Exploit identified vulnerabilities to gain unauthorized access and demonstrate attack methodology.

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
![Root Access Proof](evidence/phase2-root-access.png)

**Full Writeup:** [Phase 2 - Exploitation: vsftpd Backdoor](writeups/phase2-exploitation-vsftpd.md)

---

### 🔄 Phase 3: Post-Exploitation (Planned)

**Objectives:**
- Privilege escalation techniques
- Lateral movement concepts
- Data exfiltration methods
- Persistence mechanisms

---

### 🔄 Phase 4: Detection & Defense (Planned)

**Objectives:**
- Deploy SIEM (Security Onion or ELK Stack)
- Detect Phase 2 attack in real-time
- Write custom detection rules
- Implement system hardening controls
- Document blue team response procedures

---

## 📈 Lab Progress

- [x] Lab infrastructure configured
- [x] Network segmentation implemented  
- [x] Initial reconnaissance completed (Phase 1)
- [x] Vulnerability surface mapped
- [x] Exploitation demonstrated (Phase 2)
- [x] Root access gained via CVE-2011-2523
- [x] Attack methodology documented
- [ ] Post-exploitation analysis (Phase 3)
- [ ] Defensive hardening exercises
- [ ] SIEM/logging implementation (Phase 4)
- [ ] Detection rule development

## 🎓 Learning Outcomes

This lab demonstrates practical understanding of:
- **Offensive Security:** Attack methodologies from reconnaissance to exploitation
- **Network Security:** Proper network segmentation and isolation techniques
- **Vulnerability Management:** Systematic identification, exploitation, and remediation
- **Security Engineering:** End-to-end attack simulation and defense planning
- **Tool Proficiency:** Nmap, Metasploit Framework, Linux CLI
- **Professional Documentation:** Industry-standard penetration testing reporting

## 📝 Methodology

All exercises follow the Cyber Kill Chain and industry-standard penetration testing methodology:

1. **Reconnaissance** - Information gathering and target identification
2. **Scanning & Enumeration** - Service discovery and vulnerability mapping
3. **Exploitation** - Gaining unauthorized access
4. **Post-Exploitation** - System enumeration and privilege escalation
5. **Reporting** - Professional documentation with remediation guidance

Each phase is documented with:
- Clear objectives and scope
- Detailed methodology and commands
- Visual evidence (screenshots, diagrams)
- Findings with risk assessment
- Remediation recommendations
- Lessons learned

## 🔧 Resources

### Reference Documentation
- [Metasploit Framework Cheat Sheet](resources/metasploit-cheatsheet.md) - Quick reference for common Metasploit commands and workflows

### Lab Files
- **Writeups:** Detailed attack documentation for each phase
- **Evidence:** Screenshots and proof of successful exploitation
- **Resources:** Reference guides and cheat sheets

## 🔐 Security & Ethics

**This laboratory environment is maintained for educational purposes and professional skill development.**

- All activities conducted in isolated, controlled environment
- No connection to production systems or networks
- No unauthorized access to external systems
- Follows responsible disclosure and ethical hacking principles

**Target System:**
- Metasploitable 2 - Intentionally vulnerable training platform
- Designed for penetration testing practice
- No real data or services at risk

---

## 📚 References

- **Metasploit Framework:** https://www.metasploit.com/
- **Offensive Security:** https://www.offensive-security.com/
- **NIST Cybersecurity Framework:** https://www.nist.gov/cyberframework
- **MITRE ATT&CK:** https://attack.mitre.org/
- **CVE Details:** https://www.cvedetails.com/

---

**Last Updated:** February 6, 2026

**Current Phase:** Post-Exploitation (Phase 3 - Planning)
