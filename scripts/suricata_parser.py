#!/usr/bin/env python3
"""
Suricata Fast.log Parser
Author: Jordan Tripp
GitHub: github.com/Trippalot/security-homelab

Purpose: Parse Suricata fast.log file and generate security alert summary
Input: /var/log/suricata/fast.log (or any fast.log file)
Output: Alert statistics, top alerts, timeline summary

This is Script #1 in the Python Security Automation series (Phase 5)
"""

import re
from collections import Counter
from datetime import datetime

# ==============================================================================
# CONFIGURATION
# ==============================================================================

# Default log file path (change this to match your system)
LOG_FILE = "/var/log/suricata/fast.log"

# Output file for the report
OUTPUT_FILE = "suricata_report.txt"

# ==============================================================================
# ALERT CLASS - Represents a single Suricata alert
# ==============================================================================

class SuricataAlert:
    """
    Represents a single Suricata alert parsed from fast.log
    
    Example alert line:
    02/12/2026-11:37:31.106894 [**] [1:2100498:7] GPL ATTACK_RESPONSE id check returned root [**] 
    [Classification: Potentially Bad Traffic] [Priority: 2] {TCP} 192.168.100.10:6200 -> 192.168.100.1:64951
    """
    
    def __init__(self, line):
        """
        Parse a single alert line and extract all components
        
        Args:
            line (str): Raw alert line from fast.log
        """
        self.raw_line = line.strip()
        self.timestamp = None
        self.signature_id = None
        self.message = None
        self.classification = None
        self.priority = None
        self.protocol = None
        self.source_ip = None
        self.source_port = None
        self.dest_ip = None
        self.dest_port = None
        
        # Parse the line
        self._parse()
    
    def _parse(self):
        """
        Internal method to parse the alert line using regular expressions
        
        This method extracts:
        - Timestamp (date and time)
        - Signature ID (rule identifier)
        - Alert message (what was detected)
        - Classification (threat category)
        - Priority (1-4, 1 being highest)
        - Protocol (TCP, UDP, ICMP, etc.)
        - Source IP and port
        - Destination IP and port
        """
        
        # Extract timestamp (MM/DD/YYYY-HH:MM:SS.microseconds)
        timestamp_pattern = r'(\d{2}/\d{2}/\d{4}-\d{2}:\d{2}:\d{2}\.\d+)'
        timestamp_match = re.search(timestamp_pattern, self.raw_line)
        if timestamp_match:
            timestamp_str = timestamp_match.group(1)
            # Convert to datetime object
            try:
                self.timestamp = datetime.strptime(timestamp_str, '%m/%d/%Y-%H:%M:%S.%f')
            except ValueError:
                self.timestamp = timestamp_str  # Keep as string if parsing fails
        
        # Extract signature ID [1:2100498:7] = [generator:sig_id:revision]
        sig_pattern = r'\[(\d+):(\d+):(\d+)\]'
        sig_match = re.search(sig_pattern, self.raw_line)
        if sig_match:
            self.signature_id = f"{sig_match.group(1)}:{sig_match.group(2)}:{sig_match.group(3)}"
        
        # Extract message (text between signature ID and Classification)
        message_pattern = r'\[\d+:\d+:\d+\]\s+(.+?)\s+\[\*\*\]'
        message_match = re.search(message_pattern, self.raw_line)
        if message_match:
            self.message = message_match.group(1).strip()
        
        # Extract classification
        class_pattern = r'\[Classification:\s+(.+?)\]'
        class_match = re.search(class_pattern, self.raw_line)
        if class_match:
            self.classification = class_match.group(1).strip()
        
        # Extract priority
        priority_pattern = r'\[Priority:\s+(\d+)\]'
        priority_match = re.search(priority_pattern, self.raw_line)
        if priority_match:
            self.priority = int(priority_match.group(1))
        
        # Extract protocol
        protocol_pattern = r'\{(\w+)\}'
        protocol_match = re.search(protocol_pattern, self.raw_line)
        if protocol_match:
            self.protocol = protocol_match.group(1)
        
        # Extract source and destination IPs/ports
        # Format: 192.168.100.10:6200 -> 192.168.100.1:64951
        ip_pattern = r'(\d+\.\d+\.\d+\.\d+):(\d+)\s+->\s+(\d+\.\d+\.\d+\.\d+):(\d+)'
        ip_match = re.search(ip_pattern, self.raw_line)
        if ip_match:
            self.source_ip = ip_match.group(1)
            self.source_port = int(ip_match.group(2))
            self.dest_ip = ip_match.group(3)
            self.dest_port = int(ip_match.group(4))
    
    def __str__(self):
        """
        String representation of the alert (for printing)
        """
        return f"[{self.timestamp}] {self.message} ({self.source_ip}:{self.source_port} -> {self.dest_ip}:{self.dest_port})"

# ==============================================================================
# MAIN PARSING FUNCTIONS
# ==============================================================================

def parse_log_file(log_file_path):
    """
    Read and parse the entire Suricata fast.log file
    
    Args:
        log_file_path (str): Path to fast.log file
        
    Returns:
        list: List of SuricataAlert objects
    """
    alerts = []
    
    try:
        # Open and read the log file
        with open(log_file_path, 'r') as f:
            for line in f:
                # Skip empty lines
                if line.strip():
                    try:
                        # Parse each line into an alert object
                        alert = SuricataAlert(line)
                        alerts.append(alert)
                    except Exception as e:
                        # If a line can't be parsed, print warning and continue
                        print(f"Warning: Could not parse line: {line[:50]}... ({e})")
                        continue
    
    except FileNotFoundError:
        print(f"Error: Log file not found at {log_file_path}")
        print("Please update the LOG_FILE variable with the correct path")
        return []
    except PermissionError:
        print(f"Error: Permission denied reading {log_file_path}")
        print("Try running with sudo: sudo python3 suricata_parser.py")
        return []
    
    return alerts

def generate_statistics(alerts):
    """
    Generate statistics from parsed alerts
    
    Args:
        alerts (list): List of SuricataAlert objects
        
    Returns:
        dict: Statistics dictionary containing various metrics
    """
    stats = {
        'total_alerts': len(alerts),
        'by_priority': Counter(),
        'by_classification': Counter(),
        'by_message': Counter(),
        'by_source_ip': Counter(),
        'by_dest_port': Counter(),
        'by_protocol': Counter(),
        'timeline': []
    }
    
    # Count alerts by various attributes
    for alert in alerts:
        if alert.priority:
            stats['by_priority'][alert.priority] += 1
        if alert.classification:
            stats['by_classification'][alert.classification] += 1
        if alert.message:
            stats['by_message'][alert.message] += 1
        if alert.source_ip:
            stats['by_source_ip'][alert.source_ip] += 1
        if alert.dest_port:
            stats['by_dest_port'][alert.dest_port] += 1
        if alert.protocol:
            stats['by_protocol'][alert.protocol] += 1
        if alert.timestamp:
            stats['timeline'].append(alert.timestamp)
    
    # Sort timeline
    stats['timeline'].sort()
    
    return stats

def generate_report(stats, alerts, output_file):
    """
    Generate a human-readable report and save to file
    
    Args:
        stats (dict): Statistics dictionary
        alerts (list): List of all alerts
        output_file (str): Path to output file
    """
    
    # Create report content
    report_lines = []
    report_lines.append("=" * 80)
    report_lines.append("SURICATA ALERT ANALYSIS REPORT")
    report_lines.append("=" * 80)
    report_lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    report_lines.append("")
    
    # Overall statistics
    report_lines.append("-" * 80)
    report_lines.append("OVERALL STATISTICS")
    report_lines.append("-" * 80)
    report_lines.append(f"Total Alerts: {stats['total_alerts']}")
    report_lines.append("")
    
    # Timeline
    if stats['timeline']:
        report_lines.append(f"First Alert: {stats['timeline'][0]}")
        report_lines.append(f"Last Alert:  {stats['timeline'][-1]}")
        if len(stats['timeline']) > 1:
            duration = stats['timeline'][-1] - stats['timeline'][0]
            report_lines.append(f"Time Span:   {duration}")
    report_lines.append("")
    
    # Alerts by Priority
    report_lines.append("-" * 80)
    report_lines.append("ALERTS BY PRIORITY")
    report_lines.append("-" * 80)
    if stats['by_priority']:
        for priority in sorted(stats['by_priority'].keys()):
            count = stats['by_priority'][priority]
            percentage = (count / stats['total_alerts']) * 100
            priority_label = {1: "Critical", 2: "High", 3: "Medium", 4: "Low"}.get(priority, "Unknown")
            report_lines.append(f"Priority {priority} ({priority_label:8s}): {count:4d} alerts ({percentage:5.1f}%)")
    else:
        report_lines.append("No priority data available")
    report_lines.append("")
    
    # Top 10 Alert Types
    report_lines.append("-" * 80)
    report_lines.append("TOP 10 ALERT TYPES")
    report_lines.append("-" * 80)
    if stats['by_message']:
        for message, count in stats['by_message'].most_common(10):
            percentage = (count / stats['total_alerts']) * 100
            report_lines.append(f"{count:4d} ({percentage:5.1f}%) - {message}")
    else:
        report_lines.append("No alert messages found")
    report_lines.append("")
    
    # Top Source IPs
    report_lines.append("-" * 80)
    report_lines.append("TOP SOURCE IPs (Potential Attackers)")
    report_lines.append("-" * 80)
    if stats['by_source_ip']:
        for ip, count in stats['by_source_ip'].most_common(10):
            percentage = (count / stats['total_alerts']) * 100
            report_lines.append(f"{ip:15s} - {count:4d} alerts ({percentage:5.1f}%)")
    else:
        report_lines.append("No source IP data available")
    report_lines.append("")
    
    # Top Destination Ports
    report_lines.append("-" * 80)
    report_lines.append("TOP DESTINATION PORTS (Targeted Services)")
    report_lines.append("-" * 80)
    if stats['by_dest_port']:
        for port, count in stats['by_dest_port'].most_common(10):
            percentage = (count / stats['total_alerts']) * 100
            # Common port labels
            port_labels = {21: "FTP", 22: "SSH", 23: "Telnet", 80: "HTTP", 443: "HTTPS", 
                          139: "NetBIOS", 445: "SMB", 3306: "MySQL", 6200: "vsftpd backdoor"}
            port_label = port_labels.get(port, "Unknown")
            report_lines.append(f"Port {port:5d} ({port_label:15s}) - {count:4d} alerts ({percentage:5.1f}%)")
    else:
        report_lines.append("No destination port data available")
    report_lines.append("")
    
    # Classifications
    report_lines.append("-" * 80)
    report_lines.append("ALERT CLASSIFICATIONS")
    report_lines.append("-" * 80)
    if stats['by_classification']:
        for classification, count in stats['by_classification'].most_common():
            percentage = (count / stats['total_alerts']) * 100
            report_lines.append(f"{count:4d} ({percentage:5.1f}%) - {classification}")
    else:
        report_lines.append("No classification data available")
    report_lines.append("")
    
    # Protocols
    report_lines.append("-" * 80)
    report_lines.append("PROTOCOLS")
    report_lines.append("-" * 80)
    if stats['by_protocol']:
        for protocol, count in stats['by_protocol'].most_common():
            percentage = (count / stats['total_alerts']) * 100
            report_lines.append(f"{protocol:10s} - {count:4d} alerts ({percentage:5.1f}%)")
    else:
        report_lines.append("No protocol data available")
    report_lines.append("")
    
    # Recent Alerts (last 10)
    report_lines.append("-" * 80)
    report_lines.append("MOST RECENT ALERTS (Last 10)")
    report_lines.append("-" * 80)
    if alerts:
        # Sort by timestamp and get last 10
        sorted_alerts = sorted([a for a in alerts if a.timestamp], 
                              key=lambda x: x.timestamp, 
                              reverse=True)[:10]
        for alert in sorted_alerts:
            report_lines.append(str(alert))
    else:
        report_lines.append("No recent alerts")
    report_lines.append("")
    
    report_lines.append("=" * 80)
    report_lines.append("END OF REPORT")
    report_lines.append("=" * 80)
    
    # Join all lines with newlines
    report_content = "\n".join(report_lines)
    
    # Write to file
    try:
        with open(output_file, 'w') as f:
            f.write(report_content)
        print(f"\n✓ Report saved to: {output_file}")
    except PermissionError:
        print(f"\nError: Permission denied writing to {output_file}")
        print("Printing report to console instead:\n")
        print(report_content)
    
    # Also print to console
    print("\n" + report_content)

# ==============================================================================
# MAIN EXECUTION
# ==============================================================================

def main():
    """
    Main function - orchestrates the entire parsing and reporting process
    """
    
    print("=" * 80)
    print("SURICATA LOG PARSER")
    print("=" * 80)
    print(f"Parsing log file: {LOG_FILE}")
    print("Please wait...\n")
    
    # Step 1: Parse the log file
    alerts = parse_log_file(LOG_FILE)
    
    if not alerts:
        print("\nNo alerts found or could not read log file.")
        print("Please check:")
        print("1. Log file path is correct")
        print("2. You have permission to read the file (try: sudo python3 suricata_parser.py)")
        print("3. The log file contains alerts")
        return
    
    print(f"✓ Successfully parsed {len(alerts)} alerts\n")
    
    # Step 2: Generate statistics
    print("Generating statistics...")
    stats = generate_statistics(alerts)
    print("✓ Statistics generated\n")
    
    # Step 3: Generate and save report
    print("Creating report...")
    generate_report(stats, alerts, OUTPUT_FILE)
    
    print("\n" + "=" * 80)
    print("ANALYSIS COMPLETE")
    print("=" * 80)

# ==============================================================================
# SCRIPT ENTRY POINT
# ==============================================================================

if __name__ == "__main__":
    # This runs when the script is executed directly
    # (not when imported as a module)
    main()
