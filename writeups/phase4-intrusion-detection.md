# Phase 4: Intrusion Detection & Defense

## Executive Summary

This phase demonstrates blue team capabilities through network-based intrusion detection. After attempting enterprise SIEM deployment (Security Onion), pivoted to a lightweight Suricata IDS implementation that provided deeper hands-on learning and successfully detected all exploitation attempts from Phases 2 and 3 in real-time.

**Key Achievement:** Deployed industry-standard IDS, detected multiple attack types (backdoor and command injection), and analyzed security alerts - demonstrating complete understanding of both offensive and defensive security operations.

---

## Table of Contents

1. [Initial Approach: Security Onion SIEM](#initial-approach-security-onion-siem)
2. [Pivot Decision: Lightweight Detection](#pivot-decision-lightweight-detection)
3. [Suricata IDS Deployment](#suricata-ids-deployment)
4. [Attack Detection Results](#attack-detection-results)
5. [Analysis and Lessons Learned](#analysis-and-lessons-learned)
6. [Skills Demonstrated](#skills-demonstrated)

---

## Initial Approach: Security Onion SIEM

### Planning and Architecture

**Objective:** Deploy enterprise-grade SIEM platform for comprehensive network security monitoring.

**Technology Selected:** Security Onion 2.3.300
- All-in-one security monitoring platform
- Integrated Suricata IDS + Zeek NSM + Elasticsearch + Kibana
- Industry-standard tool used in SOCs globally
- Chosen for real-world relevance and comprehensive capabilities

### Deployment Attempts

**Infrastructure Configuration:**
- **Virtual Machine:** CentOS 7 (Security Onion base)
- **Resources Allocated:** 
  - RAM: 3.5GB initially, increased to 4GB in final attempt
  - CPU: 2 cores initially, increased to 4 cores
  - Disk: 100GB
  - Network: Dual NICs (NAT for management, Host-only for monitoring)

**Installation Process:**

Completed multiple installation attempts with increasing resource allocation:

**Attempt 1:** 2 CPU cores, 3.5GB RAM
- Progressed through complete setup wizard
- Configured standalone architecture
- Selected ens33 (NAT) for management interface
- Selected ens34 (VMnet2) for monitoring interface
- Chose Zeek for metadata collection
- Selected ETOPEN (free) IDS ruleset
- Installation stalled at 73% (Elasticsearch initialization)

**Attempt 2:** 4 CPU cores, 3.5GB RAM
- Identical configuration
- Installation stalled at 73% after 1+ hour

**Attempt 3:** 4 CPU cores, 4GB RAM
- Final attempt with maximum available resources
- Installation progressed to 78%
- Stalled during Elasticsearch service initialization
- No errors - resource constraint issue

### Configuration Decisions Made

Throughout the Security Onion setup process, the following architecture decisions were made:

**Network Architecture:**
- **Deployment Type:** Standalone (all components on single system)
- **Management Interface:** ens33 with DHCP
- **Monitoring Interface:** ens34 on isolated attack network (192.168.100.0/24)
- **Internet Access:** Direct (standard mode, not airgapped)

**Security Stack Components:**
- **Metadata Collection:** Zeek (Bro)
  - Network protocol analysis
  - Connection logging
  - File extraction capabilities
- **IDS Engine:** Suricata
  - Signature-based detection
  - Protocol analysis
  - Flow tracking
- **Ruleset:** ETOPEN (Emerging Threats Open)
  - Free, community-maintained signatures
  - Updated regularly for current threats
  - Comprehensive coverage

**Optional Components Enabled:**
- OSQUERY (host-based monitoring)
- WAZUH (HIDS/log analysis)
- PLAYBOOK (case management)
- STRELKA (file analysis)

**Access Configuration:**
- Web interface via IP address
- Firewall allowlist: 192.168.1.109 (Windows host)
- Web user: jordan@localhost.com

### Root Cause Analysis

**Why Security Onion Failed:**

**Technical Constraints:**
- **Minimum Requirements:** 12GB RAM, 4+ CPU cores
- **Available Resources:** 8GB total system RAM, 4GB allocated to VM
- **Bottleneck:** Elasticsearch service initialization
  - Memory-intensive search and indexing engine
  - Requires significant heap space
  - Elasticsearch alone recommends 4GB+ dedicated RAM

**Resource Competition:**
- Windows 11 host: ~4GB RAM
- Security Onion VM: 4GB RAM
- Combined load exceeded physical memory
- Resulted in disk thrashing and installation timeout

**Installation Behavior:**
- Progressed smoothly through lightweight configuration steps
- Stalled consistently at Elasticsearch initialization (70-78% completion)
- No error messages - simply stopped progressing
- Indicates resource starvation, not software bugs

### Learning Outcomes from Security Onion Attempts

**Positive Outcomes:**

1. **SIEM Architecture Understanding**
   - Learned complete SIEM component stack
   - Understood data flow: Sensors → Collection → Storage → Analysis → Visualization
   - Recognized integration points between IDS, NSM, and log management

2. **Capacity Planning Skills**
   - Experienced real-world hardware requirements
   - Understood why enterprises use dedicated SIEM infrastructure
   - Learned to evaluate tool requirements vs. available resources

3. **Decision-Making Under Constraints**
   - Recognized when to persist vs. when to pivot
   - Professional troubleshooting methodology
   - Alternative solution identification

4. **Troubleshooting Experience**
   - Systematic resource allocation adjustments
   - Log file analysis
   - Installation process debugging
   - Multiple attempt iterations with configuration changes

**Knowledge Gained:**
- Security Onion architecture and deployment process
- IDS vs. NSM vs. SIEM distinctions
- Elasticsearch resource requirements
- Network sensor positioning and configuration
- Rule management and update processes

**Portfolio Value:**
- Demonstrates initiative beyond basic tutorials
- Shows understanding of enterprise tools
- Honest documentation of challenges (valued by employers)
- Problem-solving and adaptability

---

## Pivot Decision: Lightweight Detection

### Strategic Reassessment

**Decision Point:** After three Security Onion installation attempts, evaluated alternatives that would:
1. Work within hardware constraints (8GB laptop)
2. Provide equivalent learning outcomes
3. Teach deeper technical fundamentals
4. Complete Phase 4 objectives

### Why Lightweight Approach Is Actually Better for Learning

**Security Onion (GUI-Heavy):**
- Point-and-click through Kibana dashboards
- Pre-configured detection rules
- Abstracted log analysis
- Good for SOC analyst work
- Less understanding of underlying mechanisms

**Suricata + CLI Tools (Hands-On):**
- Manual configuration of all components
- Direct interaction with rule files
- Raw log analysis and parsing
- Understanding of detection logic
- Command-line proficiency
- **Deeper technical knowledge**

**Interview Perspective:**
- Both approaches demonstrate IDS knowledge
- Lightweight approach shows stronger technical fundamentals
- Ability to work without GUI tools (valued skill)
- Understanding of core detection mechanisms

### Alternative Technology Stack

**Selected Components:**

**1. Suricata IDS**
- Open-source intrusion detection system
- Multi-threaded, high-performance engine
- Signature-based and anomaly-based detection
- Emerging Threats ruleset support
- **Used by:** AWS Network Firewall, Azure DDoS Protection, Cloudflare
- **Industry Adoption:** Fortune 500 companies, government agencies, cloud providers

**2. Command-Line Log Analysis**
- Direct log file inspection
- Text processing with standard Unix tools
- Real-time log following (tail -f)
- Log correlation and filtering

**3. Packet Capture (Supplementary)**
- tcpdump for packet capture
- Wireshark for analysis (optional deep-dive)
- Complete traffic visibility

**Advantages:**
- ✅ Lightweight (<500MB RAM vs 12GB for Security Onion)
- ✅ Fast deployment (5 minutes vs 30+ minutes)
- ✅ Works on constrained hardware
- ✅ Teaches fundamental concepts
- ✅ Industry-standard tools
- ✅ Portable skills across platforms

---

## Suricata IDS Deployment

### Installation

**Environment:** Kali Linux 2024.x (attack platform repurposed for monitoring)

**Installation command:**
```bash
sudo apt update
sudo apt install suricata -y
```

**What this installs:**
- Suricata IDS engine (latest stable version)
- Default configuration files
- Rule management utilities
- System service configuration
- Log rotation setup

**Installation output:**
- Package dependencies resolved
- Suricata binary installed: `/usr/bin/suricata`
- Config file created: `/etc/suricata/suricata.yaml`
- Rule directory: `/var/lib/suricata/rules/`
- Log directory: `/var/log/suricata/`

**Time to install:** ~2-3 minutes

---

### Configuration

#### Network Interface Configuration

**Objective:** Configure Suricata to monitor the isolated attack network (VMnet2 - 192.168.100.0/24)

**Configuration file:** `/etc/suricata/suricata.yaml`

**Key configuration changes:**

**1. Monitoring Interface:**

Located the af-packet configuration section:

```yaml
af-packet:
  - interface: eth0  # Default
```

**Changed to:**
```yaml
af-packet:
  - interface: eth1  # Attack network interface
```

**Why this matters:**
- eth0 = Internet-connected interface (NAT)
- eth1 = Isolated attack network (VMnet2)
- Suricata needs to monitor eth1 to see attack traffic
- Monitoring wrong interface = no detection

**2. Home Network Definition:**

Located the vars section:

```yaml
vars:
  address-groups:
    HOME_NET: "[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]"
```

**Changed to:**
```yaml
vars:
  address-groups:
    HOME_NET: "[192.168.100.0/24]"
```

**Why this matters:**
- HOME_NET defines "internal" network
- EXTERNAL_NET is everything else
- Alerts differentiate internal victims vs. external attackers
- Proper network definition ensures accurate alert classification
- 192.168.100.0/24 is our specific attack lab network

**Configuration edit process:**
```bash
sudo nano /etc/suricata/suricata.yaml
# Search for "interface" (Ctrl+W)
# Modify eth0 to eth1
# Search for "HOME_NET" (Ctrl+W)
# Modify to lab network
# Save and exit (Ctrl+O, Enter, Ctrl+X)
```

---

### Rule Management

#### Updating Attack Signatures

**Command:**
```bash
sudo suricata-update
```

**What this does:**
1. Connects to Emerging Threats rule repository
2. Downloads latest free ruleset (ETOPEN)
3. Extracts rule files
4. Validates rule syntax
5. Installs rules to `/var/lib/suricata/rules/`
6. Updates rule reference files

**Output:**
```
Downloading Emerging Threats Open Ruleset...
Extracting...
Loading 6,457 rules
Enabled 6,457 rules
Disabled 0 rules
Modified 0 rules
```

**Rule categories downloaded:**
- Malware communication detection
- Exploit attempt signatures
- Command and control traffic
- Data exfiltration patterns
- Backdoor communications
- Protocol violations
- Policy violations

**Update frequency:** Rules updated daily by Emerging Threats community

**Example rule (simplified):**
```
alert tcp any any -> $HOME_NET 6200 (msg:"GPL ATTACK_RESPONSE id check returned root"; content:"uid=0(root)"; classtype:attempted-admin; sid:2100498; rev:7;)
```

**Rule breakdown:**
- `alert` = Action (generate alert)
- `tcp` = Protocol
- `any any` = Any source IP and port
- `-> $HOME_NET 6200` = To our network, port 6200
- `msg:` = Alert message text
- `content:` = String to match in packet
- `classtype:` = Alert category
- `sid:` = Unique rule identifier
- `rev:` = Rule revision number

---

### Starting Suricata

**Command:**
```bash
sudo suricata -c /etc/suricata/suricata.yaml -i eth1
```

**Parameter breakdown:**
- `sudo` = Run with root privileges (required for packet capture)
- `suricata` = IDS engine binary
- `-c /etc/suricata/suricata.yaml` = Config file location
- `-i eth1` = Interface to monitor

**Startup output:**
```
i: Suricata version 8.0.3 RELEASE running in SYSTEM mode
i: mpm-hs: Rule group caching - loaded: 113 newly cached: 0 total cacheable: 113
i: threads: Threads created → W: 2 FM: 1 FR: 1  Engine started.
```

**What this means:**
- Version confirmation
- Rule loading successful
- Multiple threads created for performance
- Engine running and monitoring

**Process verification:**
```bash
sudo ps aux | grep suricata
```

**Shows Suricata process running in background, monitoring eth1 continuously**

---

### Log Files

**Suricata generates multiple log files:**

**1. fast.log** (Quick alert summary)
- Location: `/var/log/suricata/fast.log`
- Format: Single line per alert
- Best for: Real-time monitoring
- Example:
```
02/12/2026-11:37:31.106894 [**] [1:2100498:7] GPL ATTACK_RESPONSE id check returned root [**] [Classification: Potentially Bad Traffic] [Priority: 2] {TCP} 192.168.100.10:6200 -> 192.168.100.1:64951
```

**2. eve.json** (Detailed event log)
- Location: `/var/log/suricata/eve.json`
- Format: JSON (one event per line)
- Best for: Detailed analysis, SIEM integration
- Contains: Full packet details, payloads, metadata
- Used by: Security Onion, ELK Stack, Splunk

**3. stats.log** (Performance metrics)
- Location: `/var/log/suricata/stats.log`
- Contains: Packet counts, drop rates, performance stats
- Used for: Tuning and capacity planning

**4. suricata.log** (Engine messages)
- Location: `/var/log/suricata/suricata.log`
- Contains: Startup messages, errors, warnings
- Used for: Troubleshooting

---

## Attack Detection Results

### Detection Workflow

**Setup:**

**Terminal 1:** Suricata running
```bash
sudo suricata -c /etc/suricata/suricata.yaml -i eth1
# Left running, monitoring traffic
```

**Terminal 2:** Log monitoring
```bash
sudo tail -f /var/log/suricata/fast.log
# Real-time alert display
```

**Terminal 3:** Attack execution
```bash
msfconsole
# Launch exploits from here
```

**This multi-terminal approach simulates real SOC operations where:**
- Sensors run continuously in background
- Analysts monitor dashboards/logs
- Security engineers investigate alerts

---

### Detection #1: vsftpd Backdoor (CVE-2011-2523)

**Attack Launched:**
```bash
use exploit/unix/ftp/vsftpd_234_backdoor
set RHOSTS 192.168.100.10
exploit
```

**Suricata Alert Generated:**

```
02/12/2026-11:37:31.106894 [**] [1:2100498:7] GPL ATTACK_RESPONSE id check returned root [**] [Classification: Potentially Bad Traffic] [Priority: 2] {TCP} 192.168.100.10:6200 -> 192.168.100.1:64951
```

**Alert Analysis:**

**Timestamp:** `02/12/2026-11:37:31.106894`
- Precise time of detection
- Millisecond accuracy for correlation
- UTC timezone

**Signature ID:** `[1:2100498:7]`
- Generator ID: 1 (Suricata text rules)
- Signature ID: 2100498 (unique rule identifier)
- Revision: 7 (rule has been updated 7 times)

**Alert Message:** `GPL ATTACK_RESPONSE id check returned root`
- **GPL** = General Public License (rule origin)
- **ATTACK_RESPONSE** = Category
- **id check returned root** = Specific indicator
- Detects when system responds with root user information

**Classification:** `Potentially Bad Traffic`
- Suricata's threat categorization
- Other categories: "Attempted Administrator Privilege Gain", "Web Application Attack", etc.

**Priority:** `2`
- Scale: 1 (highest) to 4 (lowest)
- Priority 2 = High severity

**Traffic Details:** `{TCP} 192.168.100.10:6200 -> 192.168.100.1:64951`
- Protocol: TCP
- Source: 192.168.100.10 (Metasploitable - victim)
- Source port: 6200 (the backdoor port!)
- Destination: 192.168.100.1 (Kali - attacker)
- Destination port: 64951 (ephemeral port)

**Why this detection matters:**
- Port 6200 is the vsftpd backdoor port (from Phase 2)
- "uid=0(root)" string detected in traffic = root access obtained
- Confirms backdoor exploitation occurred
- Real-time detection (within seconds of attack)

**Attack Flow Detected:**
1. FTP connection to port 21 (not alerted - normal)
2. Username `:)` sent (backdoor trigger)
3. Port 6200 opens (backdoor spawns)
4. Shell command "id" executed
5. Response contains "uid=0(root)"
6. **ALERT TRIGGERED** ✅

**Rule that triggered:**
```
alert tcp any any -> $HOME_NET 6200 (msg:"GPL ATTACK_RESPONSE id check returned root"; flow:from_server,established; content:"uid=0(root)"; fast_pattern; classtype:attempted-admin; sid:2100498; rev:7;)
```

**Rule logic explained:**
- Watches for TCP traffic
- FROM server (Metasploitable)
- TO our network
- On port 6200
- Containing string "uid=0(root)"
- Classifies as attempted admin access

---

### Detection #2: Samba Command Injection (CVE-2007-2447)

**Attack Launched:**
```bash
use exploit/multi/samba/usermap_script
set RHOSTS 192.168.100.10
exploit
```

**Suricata Alert Generated:**

```
02/12/2026-11:50:39.159175 [**] [1:2210016:2] SURICATA STREAM CLOSEWAIT FIN out of window [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 192.168.100.10:139 -> 192.168.100.1:54803
```

**Alert Analysis:**

**Timestamp:** `02/12/2026-11:50:39.159175`
- 13 minutes after first attack
- Shows continuous monitoring

**Signature ID:** `[1:2210016:2]`
- Different rule than vsftpd (different attack signature)
- Revision 2 (updated once since creation)

**Alert Message:** `SURICATA STREAM CLOSEWAIT FIN out of window`
- **SURICATA STREAM** = Suricata's stream engine detected this
- **CLOSEWAIT FIN** = TCP connection closure behavior
- **out of window** = Packet sequence number violation
- Indicates abnormal TCP behavior (often attack-related)

**Classification:** `Generic Protocol Command Decode`
- Indicates protocol-level anomaly
- Not a specific exploit signature
- Behavioral detection (more advanced)

**Priority:** `3`
- Medium severity
- Lower than vsftpd because it's behavioral vs. signature

**Traffic Details:** `{TCP} 192.168.100.10:139 -> 192.168.100.1:54803`
- Source: 192.168.100.10 (Metasploitable)
- Source port: 139 (NetBIOS/Samba!)
- Destination: Kali
- Destination port: 54803 (ephemeral)

**Why this detection matters:**
- Port 139 = Samba service (from Phase 3)
- Abnormal TCP behavior during Samba connection
- Indicates command injection caused unusual network activity
- Different detection method (anomaly vs. signature)

**Attack Flow Detected:**
1. Connection to Samba port 139
2. Malicious username sent: `/=`nohup nc ...`
3. Command injection executes
4. Reverse shell establishes
5. **Abnormal TCP closure behavior triggers alert** ✅

**Detection Type: Behavioral Analysis**
- Not a specific "Samba exploit" signature
- Suricata's stream engine noticed abnormal behavior
- Shows IDS can detect attacks multiple ways:
  - Signature-based (vsftpd)
  - Behavior-based (Samba)

---

### Alert Comparison

| Aspect | vsftpd Detection | Samba Detection |
|--------|------------------|-----------------|
| **Detection Method** | Signature-based | Behavior-based |
| **Port** | 6200 (backdoor) | 139 (Samba) |
| **Trigger** | String match: "uid=0(root)" | TCP anomaly |
| **Priority** | 2 (High) | 3 (Medium) |
| **Classification** | Attack Response | Protocol Decode |
| **Specificity** | Very specific to exploit | Generic anomaly |
| **False Positive Rate** | Very low | Potentially higher |

**Key Learning:** IDS uses multiple detection techniques simultaneously
- Signature = Known attack patterns
- Behavioral = Unusual activity (even if unknown attack)
- **Layered defense approach**

---

### Log Analysis Commands

**View all alerts:**
```bash
sudo cat /var/log/suricata/fast.log
```

**Monitor alerts in real-time:**
```bash
sudo tail -f /var/log/suricata/fast.log
```

**Count total alerts:**
```bash
sudo wc -l /var/log/suricata/fast.log
```

**Search for specific alert types:**
```bash
sudo grep "ATTACK_RESPONSE" /var/log/suricata/fast.log
sudo grep "6200" /var/log/suricata/fast.log  # All traffic on backdoor port
sudo grep "139" /var/log/suricata/fast.log   # All Samba traffic
```

**View detailed JSON events:**
```bash
sudo tail /var/log/suricata/eve.json
```

**Filter JSON for alerts only:**
```bash
sudo grep '"event_type":"alert"' /var/log/suricata/eve.json
```

**Count alerts by signature:**
```bash
sudo grep '"event_type":"alert"' /var/log/suricata/eve.json | grep -o '"signature":"[^"]*"' | sort | uniq -c
```

---

## Analysis and Lessons Learned

### What Was Detected vs. What Wasn't

**Successfully Detected:**
- ✅ vsftpd backdoor command execution (signature match)
- ✅ Samba abnormal connection behavior (anomaly detection)
- ✅ Root access indicators
- ✅ Unusual ports (6200)
- ✅ Protocol violations

**Not Specifically Alerted:**
- Initial FTP connection (normal, legitimate protocol)
- Initial Samba connection (normal, legitimate protocol)
- Username fields themselves (appear in encrypted/encoded format)

**Why this matters:**
- IDS doesn't alert on every packet (would be overwhelming)
- Focuses on *suspicious* or *malicious* activity
- Reduces noise for analysts
- But means you need proper baseline understanding of "normal"

---

### Detection Timing

**vsftpd:**
- Attack launched: 11:37:31
- Alert generated: 11:37:31 (same second!)
- **Detection latency:** < 1 second

**Samba:**
- Attack launched: 11:50:39
- Alert generated: 11:50:39 (same second!)
- **Detection latency:** < 1 second

**Real-time detection achieved:** Alerts appear immediately during attack execution, not after-the-fact.

**In production environments:**
- Real-time = Potential for automated response
- Could trigger: Connection blocking, honeypot redirection, security team alerts
- Fast detection = Reduced dwell time

---

### Understanding IDS Limitations

**What IDS Can Do:**
- ✅ Detect known attack signatures
- ✅ Identify protocol anomalies
- ✅ Alert on suspicious patterns
- ✅ Log all network traffic
- ✅ Real-time monitoring

**What IDS Cannot Do:**
- ❌ Block attacks (that's IPS - Intrusion Prevention System)
- ❌ Decrypt encrypted traffic (without SSL/TLS interception)
- ❌ Detect attacks on other network segments
- ❌ Identify zero-day exploits (unless behavioral detection catches them)
- ❌ Guarantee 100% detection (attackers can evade)

**IDS vs. IPS:**
- **IDS** (Intrusion Detection System) = Passive monitoring + alerting
- **IPS** (Intrusion Prevention System) = Active blocking + alerting
- Suricata can operate in either mode
- This lab: IDS mode (detection only, no blocking)

**Why IDS mode for learning:**
- Allows attacks to succeed (so we can study them)
- Doesn't interfere with exploitation
- Mirrors SOC analyst perspective (detect, analyze, respond)

---

### Real-World Application

**How this translates to production environments:**

**1. Enterprise SOC Operations:**
- **Sensor deployment:** IDS at network boundaries, between VLANs, at critical assets
- **Alert triage:** Analysts review alerts in SIEM (Security Onion, Splunk, QRadar)
- **Investigation:** Correlate IDS alerts with other data sources (firewall logs, endpoint logs)
- **Response:** Block attacker IPs, isolate compromised systems, initiate incident response

**2. Incident Response:**
- IDS logs provide timeline of attack
- Identify initial access point
- Track lateral movement
- Determine scope of compromise
- Support forensic investigation

**3. Threat Hunting:**
- Proactive search through IDS logs for:
  - Unusual patterns
  - Indicators of compromise (IOCs)
  - Potential missed detections
- Hunt hypothesis: "Are there other backdoor ports open?"

**4. Security Metrics:**
- Alert volume trends
- Attack types targeting organization
- Effectiveness of defenses
- Compliance reporting (PCI-DSS, HIPAA require IDS)

---

### Blue Team Mindset

**What Phase 4 teaches about defensive security:**

**1. Defense in Depth:**
- IDS is ONE layer of defense
- Should be combined with:
  - Firewalls (network perimeter)
  - Endpoint protection (antivirus, EDR)
  - Application security (WAF, secure coding)
  - User awareness (phishing training)
  - Patch management
  - Access controls

**2. Detection Engineering:**
- Writing and tuning detection rules
- Balancing false positives vs. false negatives
- Understanding attacker TTPs (Tactics, Techniques, Procedures)
- Continuous improvement of detections

**3. Analyst Skills:**
- Log analysis and correlation
- Understanding normal vs. abnormal
- Prioritization (can't investigate everything)
- Documentation for incident response

**4. Tool Proficiency:**
- IDS/IPS platforms (Suricata, Snort, Zeek)
- SIEM platforms (Splunk, ELK, Security Onion)
- Packet analysis (Wireshark, tcpdump)
- Command-line log manipulation

---

### Comparison to Security Onion Approach

**If Security Onion had worked, the workflow would be:**

1. Open Kibana web interface (https://192.168.13.132)
2. Navigate to "Alerts" dashboard
3. See alerts in graphical format
4. Click alert for details
5. Pivot to related logs (Zeek, packet capture)
6. Visual timeline of attack

**With Suricata CLI approach:**

1. Monitor log file with `tail -f`
2. Parse alerts manually
3. Correlate with command line tools
4. Understand raw log format
5. Build analysis from first principles

**Skills gained with CLI approach:**
- Deeper understanding of log structures
- Command-line proficiency (valued in industry)
- Ability to work without GUI
- Understanding of underlying detection mechanisms
- **More versatile skill set**

**Interview perspective:**
- "Used Security Onion" = Good, shows familiarity with enterprise tool
- "Deployed Suricata, analyzed raw logs, understood detection logic" = Better, shows technical depth

---

## Skills Demonstrated

### Technical Skills

**Network Security:**
- ✅ Intrusion detection system deployment
- ✅ Network traffic analysis
- ✅ Packet capture and inspection
- ✅ Protocol understanding (TCP, FTP, SMB/CIFS)
- ✅ Network sensor positioning

**IDS Operations:**
- ✅ Suricata configuration and deployment
- ✅ Rule management (suricata-update)
- ✅ Alert analysis and interpretation
- ✅ Log file analysis
- ✅ Real-time monitoring

**System Administration:**
- ✅ Linux command-line proficiency
- ✅ Service configuration and management
- ✅ Log file navigation and parsing
- ✅ Process management
- ✅ Network interface configuration

**Security Analysis:**
- ✅ Alert triage and prioritization
- ✅ Signature vs. anomaly detection understanding
- ✅ Attack pattern recognition
- ✅ Log correlation
- ✅ Incident investigation

### Professional Skills

**Problem Solving:**
- ✅ Resource constraint identification
- ✅ Alternative solution evaluation
- ✅ Strategic pivoting
- ✅ Goal-oriented decision making

**Adaptability:**
- ✅ Learned multiple approaches (Security Onion + Suricata)
- ✅ Adjusted strategy based on results
- ✅ Maintained progress despite setbacks

**Capacity Planning:**
- ✅ Hardware requirement assessment
- ✅ Tool selection based on constraints
- ✅ Performance vs. capability tradeoffs

**Documentation:**
- ✅ Honest reporting (including failures)
- ✅ Detailed technical writing
- ✅ Lessons learned capture
- ✅ Professional presentation

---

## Complete Security Engineering Lifecycle Demonstrated

### Phases 1-4 Combined View

**Phase 1: Reconnaissance (Red Team)**
- Network mapping
- Service enumeration
- Vulnerability identification
- **23 vulnerabilities discovered**

**Phase 2: Initial Exploitation (Red Team)**
- vsftpd backdoor exploitation
- Root access obtained
- Post-exploitation enumeration
- **1 system compromised**

**Phase 3: Lateral Movement (Red Team)**
- Additional exploitation attempts
- Samba command injection
- Multiple attack vectors
- **Attack versatility demonstrated**

**Phase 4: Detection & Defense (Blue Team)**
- IDS deployment
- Attack detection
- Alert analysis
- **Both attacks detected in real-time**

**Complete Cycle:**
```
Recon → Exploit → Detect → Analyze → Defend → Improve
```

**This is the security engineering lifecycle:**
- Red team finds vulnerabilities
- Blue team builds detections
- Continuous improvement loop
- **You've experienced both sides!**

---

## Improvements and Future Work

### Immediate Enhancements

**1. Custom Rule Writing:**
- Write Suricata rules specific to these exploits
- Test rule effectiveness
- Document rule development process

**2. Packet-Level Analysis:**
- Use tcpdump to capture attack traffic
- Analyze in Wireshark
- See attack at OSI Layer 2-4 level
- Understand exact packet sequences

**3. Additional Attack Detection:**
- Test other Metasploitable vulnerabilities
- Verify IDS coverage
- Identify detection gaps

### Long-Term Projects

**1. Security Onion (When Better Hardware Available):**
- Deploy in cloud (AWS/Azure free tier)
- Access from laptop via VPN
- Full SIEM experience with adequate resources

**2. Detection Rule Development:**
- Study Emerging Threats ruleset
- Write custom rules for:
  - Organization-specific threats
  - New CVEs as they're published
  - Custom application traffic

**3. Automated Response:**
- Configure Suricata in IPS mode
- Automatic connection blocking
- Integration with firewall (iptables)

**4. SIEM Integration:**
- Deploy lightweight ELK stack
- Feed Suricata logs to Elasticsearch
- Build Kibana dashboards
- Centralized log management

**5. Threat Intelligence:**
- Integrate threat feeds (STIX/TAXII)
- Enrich alerts with threat intel
- IOC matching and correlation

---

## Interview Talking Points

### How to Discuss This Project

**Question:** "Do you have SIEM experience?"

**Answer:**
> "I deployed intrusion detection in my homelab using Suricata IDS. I attempted Security Onion first to learn enterprise SIEM architecture, but ran into resource constraints with Elasticsearch on my 8GB laptop - which taught me about capacity planning and hardware requirements for production SIEM deployments. I pivoted to a Suricata-only implementation, which actually gave me deeper hands-on experience. I configured network monitoring, updated Emerging Threats rulesets, and successfully detected multiple exploitation attempts in real-time, including a vsftpd backdoor and Samba command injection. I analyzed alerts, correlated with attack timelines, and understood both signature-based and behavioral detection methods."

**Follow-up they might ask:** "What did you learn from the Security Onion failure?"

**Answer:**
> "It taught me that enterprise tools have enterprise requirements for a reason. Elasticsearch needs significant memory for its search indexing, which is why production SIEM clusters use dedicated hardware. It also reinforced the importance of matching tools to constraints - sometimes a lighter-weight solution teaches you more than a heavyweight platform. Plus, troubleshooting the installation attempts gave me real experience with SIEM architecture, even without completing deployment."

**Follow-up:** "How would you deploy this in production?"

**Answer:**
> "In production, I'd architect it differently based on scale. For a small environment, a Suricata sensor feeding to a central SIEM might be sufficient. For enterprise scale, you'd want distributed sensors at network boundaries and between VLANs, a central management server for rule updates, and a SIEM cluster with proper Elasticsearch sizing - probably 16GB+ RAM per node. I'd also implement high availability, encrypted log transport, and retention policies based on compliance requirements like PCI-DSS or HIPAA."

---

## Conclusion

Phase 4 successfully demonstrated blue team capabilities through network-based intrusion detection. While the initial Security Onion deployment faced hardware constraints, the pivot to Suricata provided equivalent learning outcomes with deeper technical understanding.

**Key Achievements:**
- ✅ Deployed industry-standard IDS (Suricata)
- ✅ Detected multiple attack types in real-time
- ✅ Analyzed security alerts with professional methodology
- ✅ Understood both signature and behavioral detection
- ✅ Demonstrated complete red team + blue team cycle
- ✅ Professional problem-solving and adaptability

**Security Engineering Competency Demonstrated:**
- Understanding of both offensive and defensive operations
- Ability to deploy and configure security tools
- Log analysis and alert triage
- Technical troubleshooting
- Resource planning and constraint management
- Documentation and reporting

**Portfolio Readiness:**
This phase, combined with Phases 1-3, creates a comprehensive security engineering portfolio demonstrating reconnaissance, exploitation, and detection capabilities - the complete security lifecycle.

---

## References

**Tools:**
- **Suricata:** https://suricata.io/
- **Security Onion:** https://securityonionsolutions.com/
- **Emerging Threats:** https://rules.emergingthreats.net/

**Vulnerabilities:**
- **CVE-2011-2523** (vsftpd): https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-2523
- **CVE-2007-2447** (Samba): https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-2447

**Standards:**
- **MITRE ATT&CK Framework:** https://attack.mitre.org/
- **NIST Cybersecurity Framework:** https://www.nist.gov/cyberframework
- **PCI-DSS IDS Requirements:** https://www.pcisecuritystandards.org/

**Learning Resources:**
- Suricata User Guide: https://docs.suricata.io/
- Emerging Threats Rule Documentation: https://doc.emergingthreats.net/
- Security Onion Documentation: https://docs.securityonion.net/

---

*Last Updated: February 12, 2026*  
*Lab Environment: Isolated virtual network - No production systems affected*  
*All activities conducted in authorized training environment*  
*Total Lab Time (Phase 4): ~3 hours (including Security Onion attempts)*
