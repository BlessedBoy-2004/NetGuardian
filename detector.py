import sqlite3
from datetime import datetime
from scapy.all import *
from mitreattack.stix20 import MitreAttackData

# Initialize MITRE Data
attack_data = MitreAttackData("enterprise-attack.json")

# Database Connection
conn = sqlite3.connect('threats.db')
c = conn.cursor()

# Predefined MITRE IDs (No API calls needed)
MITRE_MAPPING = {
    "port_scan": {
        "tactic": "TA0007",  # Discovery
        "technique": "T1046"  # Network Service Discovery
    },
    "sqli": {
        "tactic": "TA0001",  # Initial Access
        "technique": "T1190"  # Exploit Public-Facing Application
    }
}

def log_threat(ip, threat_type):
    """Log threats using predefined MITRE mappings"""
    mapping = MITRE_MAPPING[threat_type]
    c.execute(
        "INSERT INTO threats (ip, tactic_id, technique_id, timestamp) VALUES (?, ?, ?, ?)",
        (ip, mapping["tactic"], mapping["technique"], datetime.now())
    )
    conn.commit()

def analyze_packet(packet):
    """Analyze network packets for security threats"""
    try:
        if packet.haslayer(IP) and packet.haslayer(TCP):
            src_ip = packet[IP].src
            
            # Detect SYN scans (Port Scanning)
            if packet[TCP].flags == 'S':
                log_threat(src_ip, "port_scan")
                print(f"🚨 Port scan detected from {src_ip} (MITRE: {MITRE_MAPPING['port_scan']['technique']})")

            # Detect SQL Injection patterns
            if packet.haslayer(Raw):
                payload = str(packet[Raw].load).lower()
                if any(keyword in payload for keyword in ['union select', 'sleep(', '1=1']):
                    log_threat(src_ip, "sqli")
                    print(f"🔥 SQLi attempt from {src_ip} (MITRE: {MITRE_MAPPING['sqli']['technique']}")

    except Exception as e:
        print(f"Error analyzing packet: {str(e)}")

if __name__ == "__main__":
    print("""🔍 NetGuardian - Enterprise Threat Detection
    Monitoring TCP traffic... (Press CTRL+C to stop)""")
    
    # Create table if not exists
    c.execute('''CREATE TABLE IF NOT EXISTS threats
                 (id INTEGER PRIMARY KEY,
                  ip TEXT,
                  tactic_id TEXT,
                  technique_id TEXT,
                  timestamp DATETIME)''')
    
    try:
        sniff(prn=analyze_packet, filter="tcp", store=0)
    except KeyboardInterrupt:
        print("\n🛑 Monitoring stopped")
    finally:
        conn.close()