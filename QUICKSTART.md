# Quick Start Guide

Get up and running with the SOC Mini-Engagement project in 5 minutes.

## Prerequisites

- Python 3.8 or higher
- pip (Python package manager)

## Installation

1. **Install pandas**:
```bash
pip install pandas
```

That's it! No other dependencies required.

## Run the Investigation

Execute the investigation script:

```bash
python src/investigate.py --input data/logs.csv --out output/
```

## Expected Output

You should see:

```
[*] Loading logs from: data/logs.csv
[+] Loaded 32 log entries

[*] Running brute force detection...
[+] Found 6 brute force incidents

[*] Running suspicious PowerShell detection...
[+] Found 3 suspicious PowerShell events

[*] Generating timeline...

[*] Creating findings summary...

[*] Saving results...
[+] Saved: output/findings_summary.csv
[+] Saved: output/brute_force_hits.csv
[+] Saved: output/powershell_hits.csv
[+] Saved: output/timeline.csv

============================================================
INVESTIGATION SUMMARY
============================================================
Total Events Analyzed: 32
Brute Force Incidents: 1
Suspicious PowerShell Events: 3

Severity Breakdown:
  High: 1
  Medium: 2
  Low: 1
============================================================

[+] Investigation complete! Results saved to: output/
```

## View Results

### Quick Summary
```bash
# Windows
type output\findings_summary.csv

# Linux/Mac
cat output/findings_summary.csv
```

### Detailed Findings
```bash
# Brute force details
type output\brute_force_hits.csv

# PowerShell details
type output\powershell_hits.csv

# Complete timeline
type output\timeline.csv
```

### Read the Incident Report
```bash
# Windows
type report\incident_report.md

# Linux/Mac
cat report/incident_report.md
```

## What You'll Find

### 🚨 Security Incidents Detected

1. **Brute Force Attack**
   - Target: SRV-DC01 (Domain Controller)
   - Account: admin
   - Source: 192.168.100.45
   - Result: Successful compromise after 5 failed attempts

2. **Malicious PowerShell Execution**
   - 3 suspicious PowerShell commands detected
   - Encoded commands with Base64
   - Download cradles attempting to fetch malicious payloads
   - Hidden window execution

### 📊 Output Files

| File | Description |
|------|-------------|
| `findings_summary.csv` | High-level overview of all incidents |
| `brute_force_hits.csv` | Detailed brute force attack events |
| `powershell_hits.csv` | Suspicious PowerShell with risk scores |
| `timeline.csv` | Complete chronological event timeline |

## Next Steps

1. **Review the Incident Report**: `report/incident_report.md`
   - Professional security incident documentation
   - MITRE ATT&CK mapping
   - Remediation recommendations

2. **Examine the Sigma Rules**: `detections/`
   - Production-ready detection rules
   - Can be deployed to SIEM platforms

3. **Explore the Code**: `src/`
   - Clean, well-commented Python
   - Modular detection logic
   - Reusable utility functions

## Customization

### Change Detection Thresholds

Edit `src/investigate.py` line 52:

```python
# Default: 5 failed attempts in 5 minutes
brute_force_hits = detect_brute_force(df, threshold=5, time_window_minutes=5)

# More sensitive: 3 attempts in 3 minutes
brute_force_hits = detect_brute_force(df, threshold=3, time_window_minutes=3)
```

### Use Your Own Logs

Replace `data/logs.csv` with your own log file. Required columns:

```
timestamp_utc, host, user, event_id, log_channel, source_ip, 
process_name, command_line, outcome, details
```

Timestamps must be in ISO 8601 format: `2024-03-04T10:12:05Z`

## Troubleshooting

### "pandas not found"
```bash
pip install pandas
```

### "Input file not found"
Make sure you're running from the project root directory:
```bash
# Check current directory
pwd  # Linux/Mac
cd   # Windows

# Should show project root with data/, src/, etc.
```

### "Permission denied"
On Linux/Mac, you may need to make the script executable:
```bash
chmod +x src/investigate.py
```

## Help & Documentation

### Get CLI Help
```bash
python src/investigate.py --help
```

### Full Documentation
- **README.md**: Complete project documentation
- **PORTFOLIO.md**: Skills showcase and professional highlights
- **PROJECT_SUMMARY.md**: Detailed completion checklist

## Questions?

This is a portfolio project demonstrating SOC analyst capabilities. For more information:
- Review the comprehensive README.md
- Examine the professional incident report
- Explore the well-commented source code

---

**Time to Complete**: ~5 minutes  
**Difficulty**: Beginner-friendly  
**Output**: Professional security investigation results
