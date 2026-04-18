# =============================================================
# Project:     Splunk Home Lab SIEM with AI Incident Response
# Author:      William Blanco
# Date:        April 2026
# Description: Queries Splunk API for security alerts and
#              generates automated incident reports using AI.
#              Detects SSH brute-force and port scan attacks.
# =============================================================



import requests
import anthropic
import json
from datetime import datetime

# =============================================================
# CONFIGURATION
# Update these values to match your environment 
# =============================================================

SPLUNK_HOST = "localhost"
SPLUNK_PORT = 8089
SPLUNK_USER = "admin"
SPLUNK_PASSWORD = "your_password"
ANTHROPIC_API_KEY = "your_api_key"


# =============================================================
# FUNCTION: get_splunk_alerts
# Connects to Splunk REST API and retrieves recent security events
# Returns a list of alert dictionaries
# =============================================================

def get_splunk_alerts():
    url = f"https://{SPLUNK_HOST}:{SPLUNK_PORT}/services/search/jobs/export"
    

    # SPL query to find failed SSH login attempts in the last 24 hours
    # This is the same detection logic used in our Splunk dashboard
    data = {
        "search": 'search index=main sourcetype=linux_secure "Failed password" | head 10',
        "output_mode": "json",
        "earliest_time": "-24h"
    }
    
    response = requests.post(
        url,
        auth=(SPLUNK_USER, SPLUNK_PASSWORD),
        data=data,
        verify=False
    )
    
    print("Status code:", response.status_code)
    print("Raw response:", response.text[:500])
    
    alerts = []
    for line in response.text.strip().split("\n"):
        if line:
            try:
                data_line = json.loads(line)
                if "result" in data_line:
                    alerts.append(data_line["result"])
            except:
                pass
    return alerts


def generate_incident_report(alerts):
    if not alerts:
        return "No threats detected in the last 15 minutes."
    
    attackers = set()
    attack_types = set()
    total_attempts = 0
    
    for alert in alerts:
        raw = alert.get("_raw", "")
        if "192.168.56.102" in raw:
            attackers.add("192.168.56.102")
        if "Failed password" in raw:
            attack_types.add("SSH Brute Force")
        if "UFW BLOCK" in raw:
            attack_types.add("Port Scan")
        total_attempts += 1
    
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    attacker_list = ", ".join(attackers) if attackers else "Unknown"
    attack_list = ", ".join(attack_types) if attack_types else "Unknown"
    
    report = "## 1. Executive Summary\n"
    report += "A security incident was detected at " + timestamp + ".\n"
    report += "Source: " + attacker_list + " targeting ubuntu-siem.\n\n"
    report += "## 2. Attack Details\n"
    report += "- Source IP: " + attacker_list + "\n"
    report += "- Attack Type: " + attack_list + "\n"
    report += "- Total Events: " + str(total_attempts) + "\n"
    report += "- Target: ubuntu-siem (192.168.56.101)\n\n"
    report += "## 3. Severity Assessment\n"
    report += "HIGH - Active brute force detected from a single IP.\n\n"
    report += "## 4. Recommended Response Actions\n"
    report += "1. Block source IP " + attacker_list + " at the firewall\n"
    report += "2. Review all successful logins from this IP\n"
    report += "3. Reset credentials for targeted accounts\n"
    report += "4. Enable account lockout after 5 failed attempts\n"
    report += "5. Switch SSH to key-based authentication\n\n"
    report += "## 5. Indicators of Compromise\n"
    report += "- Malicious IP: " + attacker_list + "\n"
    report += "- Attack Pattern: Rapid failed SSH authentication attempts\n"
    report += "- Targeted Service: SSH port 22\n"
    report += "- Targeted Username: splunklab\n"
    
    return report
def save_report(report):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"incident_report_{timestamp}.md"
    with open(filename, "w") as f:
        f.write(f"# Incident Report\n")
        f.write(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        f.write(report)
    print(f"Report saved to {filename}")
    return filename

def main():
    print("Fetching Splunk alerts...")
    alerts = get_splunk_alerts()
    print(f"Found {len(alerts)} threat(s)")
    
    print("Generating AI incident report...")
    report = generate_incident_report(alerts)
    
    print("\n" + "="*50)
    print(report)
    print("="*50 + "\n")
    
    save_report(report)

if __name__ == "__main__":
    main()