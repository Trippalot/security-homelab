# Security Automation Scripts

**Author:** Jordan Tripp  
**Project:** Security Engineering Home Lab - Phase 5  
**Purpose:** Automated security analysis and intelligence generation

---

## Overview

This directory contains Python scripts developed to automate security operations tasks from the homelab project. Each script addresses a specific aspect of security data processing, from log parsing to intelligence reporting.

**Why Automation?**  
Modern security operations handle thousands or millions of events daily. Manual analysis doesn't scale. These scripts demonstrate the automation workflows used in real SOC environments and security engineering roles.

---

## Scripts

### 1. Suricata Log Parser (`suricata_parser.py`)

**Purpose:** Parse Suricata IDS logs and generate comprehensive alert analysis

**Status:** ✅ Complete
**Results:** Successfully parsed 2 alerts from Phase 4 attacks (vsftpd + Samba)

**What it does:**
- Reads Suricata fast.log file
- Extracts all alert components (timestamp, signature, IPs, ports, etc.)
- Generates statistics (alert counts, top attackers, targeted services)
- Creates formatted security report

**Input:** `/var/log/suricata/fast.log` (configurable)  
**Output:** `suricata_report.txt` + console output

**Usage:**
```bash
# Basic usage (with sudo for log access)
sudo python3 suricata_parser.py

# Will generate report in current directory
```

**Key Features:**
- Regex-based parsing for flexibility
- Robust error handling
- Object-oriented design (SuricataAlert class)
- Professional report formatting
- Heavily commented for learning

**Lines of Code:** ~400  
**Development Time:** 6 hours (including learning/testing)

---

### 2. Alert Categorizer (`alert_categorizer.py`)

**Purpose:** Categorize alerts by attack type and risk level

**Status:** 📋 Planned

**Planned Features:**
- Categorize into: Reconnaissance, Exploitation, Post-Exploit, DoS, Policy Violation
- Risk scoring based on priority, attack type, target value
- Generate prioritized investigation queue
- Output CSV for tracking/reporting

**Coming Soon!**

---

### 3. Timeline Generator (`timeline_generator.py`)

**Purpose:** Generate attack timeline correlating multiple events

**Status:** 📋 Planned

**Planned Features:**
- Correlate Nmap scans, Metasploit exploits, Suricata alerts
- Show complete attack sequence with timestamps
- Identify time delta between attack and detection
- HTML timeline visualization

**Coming Soon!**

---

### 4. Nmap Parser (`nmap_parser.py`)

**Purpose:** Parse Nmap XML output and correlate with CVE database

**Status:** 📋 Planned

**Planned Features:**
- Extract services and versions from Nmap XML
- Query CVE database for each service
- Generate prioritized vulnerability report
- Integration with NVD API

**Coming Soon!**

---

### 5. Security Dashboard (`security_dashboard.py`)

**Purpose:** Unified HTML dashboard integrating all data sources

**Status:** 📋 Planned

**Planned Features:**
- Combine Nmap, Metasploit, Suricata data
- Generate interactive HTML dashboard
- Charts and visualizations
- Timeline view of complete attack lifecycle

**Coming Soon!**

---

## Installation & Setup

### Prerequisites

**Python Version:**
- Python 3.8 or higher recommended
- Tested on: Python 3.11.x (Kali Linux 2024.x)

**Required Libraries:**
```bash
# Standard library only for Script #1 (no additional install needed!)
# The following are built-in:
# - re (regular expressions)
# - collections (Counter)
# - datetime (time manipulation)
```

**For Future Scripts:**
```bash
# Install as needed when building additional scripts
pip install requests      # For API calls (CVE lookup, etc.)
pip install matplotlib    # For charts/graphs
pip install plotly        # For interactive visualizations
```

### Setup Steps

**1. Clone repository:**
```bash
git clone https://github.com/Trippalot/security-homelab.git
cd security-homelab/scripts
```

**2. Verify Python:**
```bash
python3 --version
# Should show 3.8 or higher
```

**3. Update log paths:**
```bash
# Edit scripts to match your environment
nano suricata_parser.py
# Change LOG_FILE variable to your log location
```

**4. Run scripts:**
```bash
# Most scripts need sudo for log file access
sudo python3 suricata_parser.py
```

---

## Usage Examples

### Example 1: Analyze Phase 4 Attacks

```bash
# Parse Suricata logs from Phase 4 IDS deployment
cd /path/to/security-homelab/scripts
sudo python3 suricata_parser.py

# Output will show:
# - vsftpd backdoor alerts
# - Samba command injection alerts  
# - Alert statistics and timeline
# - Report saved to suricata_report.txt
```

### Example 2: Generate Quick Stats

```bash
# Run parser and check just the statistics
sudo python3 suricata_parser.py | grep -A 10 "OVERALL STATISTICS"

# Shows:
# Total Alerts: X
# First Alert: [timestamp]
# Last Alert: [timestamp]
# etc.
```

### Example 3: Monitor New Alerts

```bash
# Run after new attacks to see updated analysis
sudo python3 suricata_parser.py

# Compare output with previous report to track changes
diff suricata_report.txt suricata_report_previous.txt
```

---

## Development Roadmap

### Phase 5A: Core Scripts (Current)
- [x] Script #1: Suricata Parser ✅
- [ ] Script #2: Alert Categorizer 📋
- [ ] Script #3: Timeline Generator 📋
- [ ] Script #4: Nmap Parser 📋
- [ ] Script #5: Security Dashboard 📋

### Phase 5B: Enhancements
- [ ] Add JSON/CSV export options
- [ ] Implement real-time monitoring
- [ ] Add GeoIP location mapping
- [ ] Create configuration files
- [ ] Add command-line arguments

### Phase 5C: Advanced Features
- [ ] Machine learning anomaly detection
- [ ] Threat intelligence integration
- [ ] Database backend for historical analysis
- [ ] REST API for programmatic access
- [ ] Web UI for dashboard

---

## File Structure

```
scripts/
├── README.md                    # This file
├── suricata_parser.py          # Script #1 - Log parser
├── alert_categorizer.py        # Script #2 - Alert categorization
├── timeline_generator.py       # Script #3 - Timeline analysis
├── nmap_parser.py             # Script #4 - Nmap parsing + CVE lookup
├── security_dashboard.py       # Script #5 - Integrated dashboard
├── requirements.txt            # Python dependencies (when needed)
└── utils/                      # Shared utility functions (future)
    ├── __init__.py
    ├── parsers.py             # Common parsing functions
    └── report_gen.py          # Report generation utilities
```

---

## Code Quality Standards

**Documentation:**
- All scripts include file-level docstrings
- All functions have docstrings explaining parameters and returns
- Inline comments explain complex logic
- README files for each major component

**Error Handling:**
- File not found exceptions
- Permission errors
- Malformed data handling
- Graceful degradation

**Code Style:**
- Follow PEP 8 style guide
- Meaningful variable names
- Modular function design
- Clear separation of concerns

**Testing:**
- Manual testing with Phase 4 data
- Edge case validation
- Performance benchmarking
- [Future: Unit tests with pytest]

---

## Contributing

This is a personal learning project, but feedback and suggestions are welcome!

**If you find issues:**
1. Check your Python version (3.8+)
2. Verify log file paths are correct
3. Ensure proper file permissions (use sudo)
4. Review script comments for configuration options

**For questions or suggestions:**
- GitHub Issues: https://github.com/Trippalot/security-homelab/issues
- LinkedIn: linkedin.com/in/jordan-tripp-cissp-gicsp-27b81b167

---

## Learning Resources

**Used in this project:**
- [Automate the Boring Stuff with Python](https://automatethe boringstu ff.com/) - Chapters 9-10 (File I/O)
- [RealPython - Reading and Writing Files](https://realpython.com/read-write-files-python/)
- [Python Regex Documentation](https://docs.python.org/3/howto/regex.html)
- [Python Collections - Counter](https://docs.python.org/3/library/collections.html#collections.Counter)

**Next steps:**
- See `../python-learning-roadmap.md` for complete Python learning guide
- Review `../writeups/phase5-automation.md` for detailed project writeup

---

## FAQ

**Q: Do I need to know Python to use these scripts?**  
A: No! The scripts are ready to run. But understanding Python helps you customize them. Check `python-learning-roadmap.md` to learn.

**Q: Why is Script #1 so heavily commented?**  
A: It's designed as a learning tool! The comments explain not just WHAT the code does, but WHY. Perfect for learning Python for security.

**Q: Can I use these scripts on real production data?**  
A: Yes, but test thoroughly first! These were built for a homelab. For production use, you'd want to add:
- Input validation
- Database storage
- Better error handling
- Performance optimization
- Configuration management

**Q: What Python version do I need?**  
A: Python 3.8+ recommended. Tested on Python 3.11.x (Kali Linux). Check your version: `python3 --version`

**Q: I get "Permission denied" errors**  
A: Log files typically require root access. Run with `sudo`: `sudo python3 suricata_parser.py`

**Q: Can I modify these scripts?**  
A: Absolutely! That's how you learn! Try:
- Changing the output format
- Adding new statistics
- Parsing different log fields
- Creating your own reports

**Q: Where's the data coming from?**  
A: These scripts analyze data from previous homelab phases:
- Phase 1: Nmap reconnaissance
- Phase 2-3: Metasploit exploitation
- Phase 4: Suricata IDS detection

---

## License

This is a personal educational project. Scripts provided as-is for learning purposes.

Feel free to use, modify, and learn from this code for your own educational projects!

---

## Acknowledgments

**Inspiration:**
- Automate the Boring Stuff with Python (Al Sweigart)
- Black Hat Python (Justin Seitz)
- Violent Python (TJ O'Connor)

**Tools:**
- Suricata IDS: https://suricata.io/
- Emerging Threats Rules: https://rules.emergingthreats.net/
- Python: https://www.python.org/

---

**Last Updated:** February 2026  
**Maintained by:** Jordan Tripp  
**Project:** https://github.com/Trippalot/security-homelab  
**Status:** Active Development 🚀
