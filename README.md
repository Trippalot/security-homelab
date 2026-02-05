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
- ✅ Vulnerability identification and assessment
- ✅ Service version detection
- ✅ Security tool proficiency (Nmap)
- ✅ Technical documentation and reporting

## 🔍 Phase 1: Network Reconnaissance

### Objective
Map the attack surface of Metasploitable 2 through systematic network reconnaissance and service enumeration.

### Methodology
1. **Connectivity Verification:** Verified network reachability using ICMP ping
2. **Port Scanning:** Performed comprehensive TCP port scan
3. **Service Detection:** Identified running services and version numbers
4. **Vulnerability Correlation:** Mapped detected versions to known CVEs

### Tools Used
- **Nmap** - Network mapper for port scanning and service detection
- **Command:** `nmap -sV -sC 192.168.100.10`
  - `-sV`: Service/version detection
  - `-sC`: Default script scan for common vulnerabilities

### Key Findings

The initial reconnaissance scan identified **23 open TCP ports** with multiple critical vulnerabilities:

#### Critical Vulnerabilities Discovered

| Port | Service | Version | Vulnerability | Severity |
|------|---------|---------|---------------|----------|
| 21 | FTP | vsftpd 2.3.4 | Backdoor (CVE-2011-2523) | 🔴 CRITICAL |
| 23 | Telnet | Linux telnetd | Unencrypted authentication | 🔴 CRITICAL |
| 80 | HTTP | Apache 2.2.8 | Multiple known exploits | 🟠 HIGH |
| 139/445 | SMB | Samba 3.x | Remote code execution | 🔴 CRITICAL |
| 3306 | MySQL | 5.0.51a | Exposed database service | 🟠 HIGH |
| 22 | SSH | OpenSSH 4.7p1 | Outdated version (2007) | 🟡 MEDIUM |

#### Notable Security Issues
- **Anonymous FTP access enabled** - Allows unauthenticated file access
- **Unencrypted Telnet** - Credentials transmitted in cleartext
- **Exposed database** - MySQL accessible over network
- **Outdated software stack** - All services running vulnerable versions from 2007-2008

### Evidence
*Nmap scan results showing extensive attack surface with vulnerable services*

![Nmap Scan Results](scans/kali_nmap_scans.png)
*Nmap service detection scan revealing 23 open ports with vulnerable services across multiple protocols*

### Impact Assessment
In a production environment, these findings would represent:
- **Immediate remote code execution risk** (vsftpd backdoor, Samba vulnerabilities)
- **Data breach potential** (exposed MySQL database)
- **Credential theft risk** (unencrypted Telnet)
- **Extensive attack surface** requiring immediate remediation

## 📈 Lab Progress

- [x] Lab infrastructure configured
- [x] Network segmentation implemented  
- [x] Initial reconnaissance completed
- [x] Vulnerability surface mapped
- [ ] Exploitation phase (next)
- [ ] Post-exploitation analysis
- [ ] Defensive hardening exercises
- [ ] SIEM/logging implementation

## 🎓 Learning Outcomes

This lab demonstrates practical understanding of:
- **Offensive Security:** Reconnaissance methodologies and attack surface analysis
- **Network Security:** Proper network segmentation and isolation techniques
- **Vulnerability Management:** Systematic identification and risk assessment
- **Security Operations:** Tool proficiency and professional documentation

## 📝 Documentation Standards

All exercises follow industry-standard penetration testing methodology:
1. Planning & Reconnaissance
2. Scanning & Enumeration  
3. Exploitation
4. Post-Exploitation
5. Reporting

Each phase is documented with:
- Clear objectives
- Methodology and tools used
- Evidence (screenshots, scan outputs)
- Findings and risk assessment
- Remediation recommendations

---

*This laboratory environment is maintained for educational purposes and professional skill development. All activities are conducted in an isolated, controlled environment with no connection to production systems.*

**Last Updated:** February 2026
```
