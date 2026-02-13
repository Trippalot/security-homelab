# Python Learning Roadmap for Security Engineers
## From Zero to Security Automation

**Author:** Jordan Tripp  
**Purpose:** Learn Python specifically for security engineering and automation  
**Time Estimate:** 40-60 hours total (can be done part-time over 4-8 weeks)

---

## Why Python for Security?

Python is THE language for security professionals because:
- ✅ Used in: Metasploit modules, exploit development, malware analysis, automation
- ✅ Easy to learn, powerful for automation
- ✅ Huge security library ecosystem (Scapy, Impacket, etc.)
- ✅ Perfect for parsing logs, analyzing data, building tools
- ✅ Industry standard for SOC automation and security engineering

---

## Learning Path Overview

```
Phase 1: Python Basics (8-12 hours)
    ↓
Phase 2: Data Manipulation (8-12 hours)
    ↓
Phase 3: File & Log Processing (6-8 hours)
    ↓
Phase 4: Security-Specific Libraries (8-12 hours)
    ↓
Phase 5: Building Security Tools (10-15 hours)
```

---

## Phase 1: Python Basics (8-12 hours)

### What You'll Learn
- Variables, data types, operators
- Control flow (if/else, loops)
- Functions and modules
- Basic input/output
- Error handling

### Resources
**Free Online:**
- ✅ [Python.org Official Tutorial](https://docs.python.org/3/tutorial/) - Chapters 1-6
- ✅ [Automate the Boring Stuff](https://automatethe boringstu ff.com/) - Chapters 1-5 (free online)
- ✅ [RealPython Basics](https://realpython.com/start-here/) - Python basics section

**Practice:**
- ✅ [HackerRank Python Track](https://www.hackerrank.com/domains/python) - First 20 challenges
- ✅ Write simple scripts: calculator, fizzbuzz, password generator

### Hands-On Project
**Build a Port Scanner (Beginner)**
```python
# Simple TCP port scanner
# Scan ports 1-100 on localhost
# Print which ports are open
```

**Skills Demonstrated:**
- Loops (for i in range(1, 101))
- Sockets (network programming basics)
- Conditionals (if port is open)
- Error handling (connection refused)

**Time:** 2-3 hours  
**Result:** Working port scanner script

---

## Phase 2: Data Manipulation (8-12 hours)

### What You'll Learn
- Lists, dictionaries, sets, tuples
- List comprehensions
- String manipulation and regex
- Working with collections
- Sorting and filtering data

### Resources
**Free Online:**
- ✅ Automate the Boring Stuff - Chapters 6-7
- ✅ [RealPython - Python Data Structures](https://realpython.com/python-data-structures/)
- ✅ [Regex Tutorial for Python](https://docs.python.org/3/howto/regex.html)

**Practice:**
- ✅ Parse Nmap output and extract IPs
- ✅ Extract email addresses from text using regex
- ✅ Count word frequencies in a file

### Hands-On Project
**Build an IP Address Analyzer**
```python
# Read a list of IP addresses
# Categorize by network (192.168.x.x, 10.x.x.x, etc.)
# Find duplicates
# Sort by subnet
# Output statistics
```

**Skills Demonstrated:**
- File reading
- Regular expressions (IP pattern matching)
- Dictionaries (categorizing by network)
- Sorting and counting

**Time:** 3-4 hours  
**Result:** IP analysis tool

---

## Phase 3: File & Log Processing (6-8 hours)

### What You'll Learn
- Reading and writing files
- CSV and JSON parsing
- Working with log files
- Path manipulation
- Batch file processing

### Resources
**Free Online:**
- ✅ Automate the Boring Stuff - Chapters 9-10
- ✅ [RealPython - Reading and Writing Files](https://realpython.com/read-write-files-python/)
- ✅ [Working with JSON in Python](https://realpython.com/python-json/)

**Practice:**
- ✅ Parse CSV files
- ✅ Search log files for patterns
- ✅ Convert between file formats (CSV → JSON)

### Hands-On Project
**Build a Log File Analyzer (THIS IS SCRIPT #1!)**
```python
# Parse Suricata fast.log
# Extract: timestamps, alert types, IPs, ports
# Generate statistics
# Create summary report
```

**Skills Demonstrated:**
- File I/O
- String parsing and regex
- Data aggregation (counting, sorting)
- Report generation

**Time:** 4-6 hours  
**Result:** Working log parser (YOU'LL BUILD THIS!)

---

## Phase 4: Security-Specific Libraries (8-12 hours)

### What You'll Learn
- **Scapy:** Packet manipulation
- **Requests:** HTTP/API interactions
- **BeautifulSoup:** Web scraping
- **Impacket:** Windows protocol implementation
- **subprocess:** Running system commands

### Resources
**Free Online:**
- ✅ [Scapy Documentation](https://scapy.readthedocs.io/)
- ✅ [Requests Quickstart](https://requests.readthedocs.io/en/latest/user/quickstart/)
- ✅ [Impacket Examples](https://github.com/fortra/impacket/tree/master/examples)

**Practice:**
- ✅ Send custom packets with Scapy
- ✅ Query CVE databases with Requests
- ✅ Run Nmap from Python and parse results

### Hands-On Projects

**Project 1: CVE Lookup Tool**
```python
# Query NVD API for CVE details
# Input: CVE number (e.g., CVE-2011-2523)
# Output: Description, CVSS score, affected versions
```

**Project 2: Automated Nmap Runner**
```python
# Run Nmap scans via subprocess
# Parse XML output
# Generate vulnerability report
```

**Time:** 8-10 hours total  
**Result:** Two working security tools

---

## Phase 5: Building Security Tools (10-15 hours)

### What You'll Build
Real security automation tools for YOUR homelab!

### Tool 1: Suricata Alert Dashboard
**What it does:**
- Parses Suricata eve.json (detailed logs)
- Generates HTML dashboard with:
  - Alert timeline
  - Top attackers
  - Attack type breakdown
  - Geographic visualization (if you add GeoIP)

**Skills Used:**
- JSON parsing
- HTML generation
- Data visualization
- File operations

**Time:** 6-8 hours  
**Result:** Interactive security dashboard

---

### Tool 2: Vulnerability Report Generator
**What it does:**
- Takes Nmap XML output
- Looks up CVEs for each service
- Generates professional PDF report with:
  - Executive summary
  - Detailed findings
  - Remediation recommendations
  - Risk scoring

**Skills Used:**
- XML parsing
- API integration (CVE database)
- PDF generation (ReportLab library)
- Professional formatting

**Time:** 8-10 hours  
**Result:** Automated vuln reporting

---

### Tool 3: Attack Correlation Engine
**What it does:**
- Reads multiple log sources:
  - Nmap reconnaissance logs
  - Metasploit exploitation logs
  - Suricata IDS alerts
- Correlates by time and IP
- Shows complete attack timeline
- Identifies undetected attacks

**Skills Used:**
- Multi-file processing
- Time correlation
- Data merging
- Timeline generation

**Time:** 10-12 hours  
**Result:** Complete attack analysis tool

---

## Python for Security: Essential Libraries

### Core Libraries (Learn These First)
```python
import re           # Regular expressions (pattern matching)
import os           # Operating system operations
import sys          # System-specific parameters
import json         # JSON parsing (API responses, eve.json)
import csv          # CSV file handling
import datetime     # Time/date manipulation
import subprocess   # Run system commands (Nmap, etc.)
import socket       # Network programming
import argparse     # Command-line argument parsing
```

### Security-Specific Libraries (Learn Next)
```python
import requests     # HTTP requests (API calls, web testing)
import scapy        # Packet manipulation
import nmap         # Python-nmap wrapper
import impacket     # Windows protocols (SMB, Kerberos)
import paramiko     # SSH automation
import cryptography # Encryption/hashing
```

### Useful but Optional
```python
import pandas       # Data analysis (overkill for most security tasks)
import matplotlib   # Graphing (for visualizations)
import flask        # Web framework (for dashboards)
```

---

## Learning Schedule (Part-Time: 8 Weeks)

### Week 1-2: Python Basics
- **Mon/Wed/Fri:** 1.5 hours each (tutorial + practice)
- **Weekend:** 3-4 hours (build port scanner project)
- **Total:** 10-12 hours

### Week 3-4: Data Manipulation
- **Mon/Wed/Fri:** 1.5 hours each (lists, dicts, regex)
- **Weekend:** 3-4 hours (build IP analyzer)
- **Total:** 10-12 hours

### Week 5: File & Log Processing
- **Mon/Wed/Fri:** 1.5 hours each (file I/O, parsing)
- **Weekend:** 4-5 hours (build Suricata parser - Script #1!)
- **Total:** 8-10 hours

### Week 6-7: Security Libraries
- **Mon/Wed/Fri:** 1.5 hours each (learn Scapy, Requests)
- **Weekend:** 4-5 hours (build CVE lookup + Nmap automation)
- **Total:** 12-14 hours

### Week 8: Capstone Project
- **Weekend intensive:** Build complete security dashboard
- **Total:** 10-12 hours

---

## Your Specific Learning Path (For Security Homelab)

### Priority Order (What You Need MOST)

**1. File Processing (Week 5)** ← START HERE
- You already have Suricata logs to parse!
- Immediate practical value
- Script #1 in your automation series
- **Action:** Complete Phase 3 above, then build Script #1

**2. Data Structures (Week 3-4)**
- Needed for Script #2 (alert categorizer)
- Required for statistics and reporting
- **Action:** Learn dictionaries, Counter, sorting

**3. Regular Expressions**
- Critical for log parsing
- Pattern matching in alerts
- **Action:** Focus on regex tutorial + practice with IP/port patterns

**4. Basic Python (Week 1-2)**
- If you're completely new, start here
- But keep it SHORT - get to file processing ASAP
- **Action:** Just learn enough to understand Script #1

---

## Quick Start Guide (If You're NEW to Python)

**Day 1 (2 hours): Install and Hello World**
```bash
# Install Python (if not already)
sudo apt install python3 python3-pip

# First script
echo 'print("Hello, Security World!")' > hello.py
python3 hello.py

# Variables and types
python3
>>> name = "Jordan"
>>> age = 25
>>> is_security_engineer = True
>>> print(f"My name is {name} and I am {age}")
```

**Day 2 (2 hours): Loops and Conditions**
```python
# For loop
for i in range(1, 11):
    print(f"Port {i}")

# If/else
port = 22
if port == 22:
    print("SSH port")
elif port == 80:
    print("HTTP port")
else:
    print("Unknown port")
```

**Day 3 (2 hours): Functions and Lists**
```python
# Function
def scan_port(ip, port):
    print(f"Scanning {ip}:{port}")
    return True

# Lists
open_ports = [22, 80, 443]
for port in open_ports:
    print(f"Port {port} is open")
```

**Day 4-5 (4 hours): File Reading**
```python
# Read a file
with open("alerts.log", "r") as f:
    for line in f:
        print(line.strip())

# Write a file
with open("report.txt", "w") as f:
    f.write("Security Report\n")
    f.write("Total alerts: 42\n")
```

**Day 6-7 (4 hours): Regex and Parsing**
```python
import re

# Find IP addresses in text
text = "Alert from 192.168.1.100 on port 6200"
ip_pattern = r'\d+\.\d+\.\d+\.\d+'
ips = re.findall(ip_pattern, text)
print(ips)  # ['192.168.1.100']

# Extract port numbers
port_pattern = r'port (\d+)'
port = re.search(port_pattern, text)
print(port.group(1))  # '6200'
```

**After 1 Week: You Can Now Understand Script #1!**

---

## Practice Challenges (Specific to Your Homelab)

### Challenge 1: Parse Your Nmap Output
```python
# Read your Phase 1 Nmap scan results
# Extract all open ports
# Count how many services are vulnerable
# Output: "Found 23 open ports across 5 services"
```

### Challenge 2: Metasploit Log Parser
```python
# Parse your Metasploit logs
# Extract successful exploits
# List target IPs and vulnerabilities exploited
# Output: Timeline of your attacks
```

### Challenge 3: Alert Counter
```python
# Read Suricata fast.log
# Count alerts by hour
# Find the busiest attack period
# Output: "Most alerts at 11:37 (5 alerts in 1 minute)"
```

---

## Common Pitfalls & Solutions

### Pitfall 1: "I don't understand everything in the script"
**Solution:** That's NORMAL! Start by running it, see what it does, THEN study how it works. You'll learn by doing.

### Pitfall 2: "Regex is confusing"
**Solution:** Use [regex101.com](https://regex101.com/) - paste your pattern, paste sample text, see what matches. Visual learning!

### Pitfall 3: "My script doesn't work"
**Solution:** 
```python
# Add debug print statements everywhere!
print(f"DEBUG: Reading file {filename}")
print(f"DEBUG: Found {len(alerts)} alerts")
print(f"DEBUG: Processing alert: {alert}")
```

### Pitfall 4: "I'm stuck on basics and not building security tools"
**Solution:** SKIP ahead to Script #1! Learn the basics AS YOU NEED THEM. Don't get stuck in tutorial hell.

---

## Recommended Learning Strategy

### The "Just-In-Time" Approach (BEST for Security Engineers)

**Traditional approach:**
1. Learn ALL Python basics (weeks)
2. Learn ALL data structures (weeks)
3. FINALLY start security projects (months later)
4. ❌ You're bored and demotivated by now

**Just-In-Time approach (RECOMMENDED):**
1. START with Script #1 (Suricata parser) ← TODAY
2. Run it (even if you don't understand everything)
3. Break it (change things, see what happens)
4. Google concepts you don't understand as you encounter them
5. Learn "dictionaries" WHEN you see `Counter()` in the script
6. Learn "regex" WHEN you see `re.search()` in the script
7. ✅ You're building tools from DAY ONE

**Result:** Functional security tool in 1 week instead of 3 months!

---

## Your First Week Action Plan

### Day 1: Setup (30 minutes)
- ✅ Verify Python installed: `python3 --version`
- ✅ Copy Script #1 to your Kali VM
- ✅ Update LOG_FILE path to your Suricata log

### Day 2: Run Script #1 (1 hour)
- ✅ Run: `python3 suricata_parser.py`
- ✅ Read the generated report
- ✅ See your Phase 4 attacks in the output!
- ✅ CELEBRATE - you just ran a Python security tool!

### Day 3: Understand Basics (2 hours)
- ✅ Read the comments in Script #1
- ✅ Learn what `with open()` does
- ✅ Learn what `for line in f:` does
- ✅ Google: "Python file reading tutorial"

### Day 4: Break and Fix (2 hours)
- ✅ Change the output filename
- ✅ Add a new statistic (e.g., count UDP vs TCP)
- ✅ Print alerts in reverse chronological order
- ✅ Google errors when things break!

### Day 5: Customize (2 hours)
- ✅ Add your name to the report header
- ✅ Change the report format
- ✅ Add color coding for priority levels
- ✅ Make it YOUR tool!

### Day 6-7: Document (3 hours)
- ✅ Create Phase 5 writeup (template provided)
- ✅ Take screenshots of your report
- ✅ Commit to GitHub
- ✅ Post on LinkedIn!

---

## Resources Quick Reference

### Free Learning
- **Python.org Tutorial:** https://docs.python.org/3/tutorial/
- **Automate the Boring Stuff:** https://automatethe boringstu ff.com/ (free online)
- **RealPython:** https://realpython.com/ (free articles)
- **W3Schools Python:** https://www.w3schools.com/python/

### Practice & Challenges
- **HackerRank:** https://www.hackerrank.com/domains/python
- **LeetCode:** https://leetcode.com/ (focus on Easy problems)
- **Python for Cybersecurity:** https://github.com/topics/python-security

### Security-Specific
- **Violent Python (book):** Classic security Python book
- **Black Hat Python (book):** Advanced security automation
- **Cybrary Python for Security:** Free course

### When You're Stuck
- **Stack Overflow:** https://stackoverflow.com/ (search your error message!)
- **Python Discord:** Real-time help from community
- **r/learnpython:** Reddit community for beginners

---

## Success Metrics

### After 1 Week:
- ✅ Can run Script #1 successfully
- ✅ Understand basic file reading
- ✅ Can modify simple variables
- ✅ Generated your first security report!

### After 1 Month:
- ✅ Built 3-4 custom security scripts
- ✅ Comfortable with lists, dictionaries, loops
- ✅ Can parse any log file format
- ✅ Automating parts of your security workflow

### After 2 Months:
- ✅ Built complete security dashboard
- ✅ Integrated multiple data sources
- ✅ Can learn new libraries independently
- ✅ Contributing to open-source security tools
- ✅ "Python Developer" added to resume!

---

## Final Advice

**Don't aim for perfection - aim for functional!**

Your first scripts will be messy. That's OK!  
You'll Google everything. That's NORMAL!  
You'll get errors. That's how you LEARN!

**The best way to learn Python for security:**
1. Start with a real security problem (parsing Suricata logs)
2. Find a script that solves it (Script #1)
3. Run it, break it, fix it, customize it
4. Learn concepts as you need them
5. Build the next tool

**You don't become a security engineer by finishing tutorials.**  
**You become one by building security tools!**

---

**START TODAY with Script #1!** 🚀

**See you in the Python security automation world!** 💪
