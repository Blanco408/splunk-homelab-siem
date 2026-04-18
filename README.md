# Splunk Home Lab SIEM with AI-Assisted Incident Response

## Project Overview
A home lab Security Information and Event Management (SIEM) system built with Splunk, Python, and AI. Simulates real-world SOC workflows by detecting cyber attacks in real time and automatically generating incident reports.

## Lab Architecture
- **Attacker:** Kali Linux (192.168.56.102)
- **Target:** Ubuntu Server 22.04 (192.168.56.101)
- **SIEM:** Splunk Enterprise (Windows host)
- **AI Triage:** Python + Anthropic Claude API

## Tools & Technologies
- Splunk Enterprise (SIEM, log ingestion, dashboards, alerting)
- Splunk Universal Forwarder (log shipping from Ubuntu Server)
- Python 3.11 (Splunk API integration, AI pipeline)
- Anthropic Claude API (automated incident report generation)
- Kali Linux (Nmap, Metasploit Framework)
- Ubuntu Server 22.04 (target machine)
- UFW (firewall logging for port scan detection)
- VirtualBox (lab virtualization)

## Attack Scenarios Detected
| Attack | Tool Used | Log Source | Detection Method |
|--------|-----------|------------|-----------------|
| SSH Brute Force | Metasploit ssh_login | /var/log/auth.log | >5 failed logins/min from single IP |
| Port Scan | Nmap -sS | /var/log/ufw.log | >15 blocked connections/min |

## SPL Detection Rules

### SSH Brute Force Detection
```spl
index=main sourcetype=linux_secure "Failed password"
| rex "from (?P<src_ip>\d+\.\d+\.\d+\.\d+)"
| bucket _time span=1m
| stats count as failed_attempts by src_ip, _time
| where failed_attempts > 5
| eval threat="SSH Brute Force Detected"
```

### Port Scan Detection
```spl
index=main sourcetype=ufw "UFW BLOCK"
| rex "SRC=(?P<src_ip>\d+\.\d+\.\d+\.\d+)"
| bucket _time span=1m
| stats count as blocked_connections by src_ip, _time
| where blocked_connections > 15
| eval threat="Port Scan Detected"
```

## AI Incident Response Pipeline
1. Python queries Splunk REST API (port 8089) for recent alerts
2. Alert data is parsed and structured
3. Data is sent to Claude AI API with SOC analyst prompt
4. AI generates plain-English incident report with severity, IOCs, and response actions
5. Report is saved as a markdown file with timestamp

## Sample Incident Report
See the `incident_report_*.md` files for sample AI-generated reports.

## How to Run
1. Clone this repo
2. Install dependencies: `pip install requests anthropic`
3. Add your Splunk credentials and Anthropic API key to `ai_triage.py`
4. Run: `python ai_triage.py`

## Skills Demonstrated
- SIEM deployment and configuration
- Log ingestion and forwarding
- SPL query writing and threat detection
- Automated alerting and dashboards
- Python scripting and REST API integration
- AI/ML integration in cybersecurity workflows
- Penetration testing (Nmap, Metasploit)
- Incident response documentation
- Linux administration and network security

## Alignment to Security+ Domains
- Domain 1: Threats, Attacks and Vulnerabilities
- Domain 2: Technologies and Tools
- Domain 3: Architecture and Design
- Domain 4: Identity and Access Management
- Domain 5: Risk Management
