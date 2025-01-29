# 🔒 NetGuardian - Network Intrusion Detection System
A Python-based IDS detecting SQLi attacks and port scans, mapped to MITRE ATT&CK framework.

## Features
- Real-time network monitoring
- SQL injection detection
- MITRE ATT&CK T1190/T1046 mapping
- Automated PDF reporting

## Installation
```bash
git clone https://github.com/BlessedBoy-2004/NetGuardian.git
cd NetGuardian
pip install -r requirements.txt
```

## Usage
```bash
# Run as Administrator
python detector.py

# Generate report
python reporter.py
```

## Tech Stack
- Python 3.10
- Scapy (packet analysis)
- SQLite (threat logging)
- ReportLab (PDF generation)

## License
MIT License - See [LICENSE](LICENSE)
