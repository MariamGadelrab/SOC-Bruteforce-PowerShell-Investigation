# Portfolio Showcase: SOC Mini-Engagement Project

## 🎯 Project Purpose

This project demonstrates my capabilities as a Senior SOC Analyst and Security Engineer through a realistic security investigation simulation. It showcases end-to-end incident response skills from detection to reporting.

## 💼 Professional Skills Demonstrated

### 1. Security Operations & Analysis
- **Log Analysis**: Parsed and analyzed 32 Windows Security and PowerShell log entries
- **Threat Detection**: Identified brute force attacks and malicious PowerShell execution
- **Incident Investigation**: Correlated events across multiple hosts and timeframes
- **IOC Extraction**: Documented malicious IPs, URLs, and behavioral indicators

### 2. Detection Engineering
- **Sigma Rules**: Developed 2 production-ready Sigma detection rules
- **Detection Logic**: Implemented sliding window analysis for brute force detection
- **Risk Scoring**: Created weighted risk scoring system for PowerShell threats
- **False Positive Management**: Documented expected false positives in rules

### 3. Python Development
- **Data Analysis**: Used pandas for efficient log processing
- **CLI Tools**: Built professional command-line interface with argparse
- **Modular Design**: Separated concerns (main script, utilities, detection logic)
- **Error Handling**: Implemented robust error handling and user feedback

### 4. Incident Response & Reporting
- **Professional Documentation**: Created comprehensive incident report
- **MITRE ATT&CK Mapping**: Mapped findings to 5 ATT&CK techniques
- **Actionable Recommendations**: Provided immediate, short-term, and long-term remediation steps
- **Executive Communication**: Wrote executive summary suitable for management

## 📊 Key Achievements

### Detection Accuracy
- ✅ Successfully detected 1 brute force attack (5 failed attempts → success)
- ✅ Identified 3 suspicious PowerShell executions with 0 false positives
- ✅ Correctly classified severity levels (1 High, 2 Medium, 1 Low)
- ✅ Generated complete timeline of 32 events with proper correlation

### Code Quality
- ✅ Clean, well-commented Python code
- ✅ Modular architecture for maintainability
- ✅ Comprehensive CLI help documentation
- ✅ Proper timestamp parsing (ISO 8601 format)
- ✅ Configurable thresholds and parameters

### Documentation Quality
- ✅ Professional incident report (2,500+ words)
- ✅ Comprehensive README with usage examples
- ✅ Detailed Sigma rules with metadata
- ✅ Clear project structure and organization

## 🔍 Technical Highlights

### Advanced Detection Techniques

**Brute Force Detection**:
- Sliding window analysis (5-minute windows)
- Grouped by host + source IP for accuracy
- Detects failed attempts followed by success
- Configurable threshold (default: 5 attempts)

**PowerShell Threat Detection**:
- Pattern matching for 7+ malicious indicators
- Base64 decoding for encoded commands
- Weighted risk scoring (0-100 scale)
- Behavioral analysis (download cradles, hidden execution)

### Data Processing
- Efficient pandas operations for large log sets
- Proper datetime handling with timezone awareness
- Deduplication of events
- Multi-level grouping and aggregation

## 🎓 Real-World Applicability

### SIEM Integration Ready
The Sigma rules can be converted to:
- Splunk SPL queries
- Elastic Query DSL
- QRadar AQL
- Microsoft Sentinel KQL

### Scalability
The Python script can be extended to:
- Query SIEM APIs directly
- Process millions of log entries
- Run as scheduled detection job
- Integrate with ticketing systems (Jira, ServiceNow)
- Send alerts via Slack/PagerDuty

### Production Deployment
This project demonstrates production-ready code:
- Error handling for missing files
- Input validation
- Clear user feedback
- Proper exit codes
- Comprehensive logging

## 📈 Metrics & Results

| Metric | Value |
|--------|-------|
| Total Log Entries | 32 |
| Hosts Analyzed | 3 (SRV-DC01, WKS-001, WKS-002) |
| Users Analyzed | 5 (admin, jdoe, asmith, bwilson, svc_backup) |
| Detections Created | 2 Sigma rules |
| Incidents Identified | 4 total (1 brute force, 3 PowerShell) |
| IOCs Extracted | 3 (1 IP, 2 URLs) |
| MITRE Techniques Mapped | 5 (T1078, T1110.001, T1059.001, T1027, T1105) |
| Lines of Code | ~400 (Python) |
| Report Length | 2,500+ words |

## 🛡️ Security Expertise Demonstrated

### Threat Intelligence
- Understanding of common attack patterns
- Knowledge of PowerShell-based attacks
- Familiarity with credential compromise techniques
- Awareness of post-exploitation activities

### Defensive Security
- Account lockout policy recommendations
- MFA implementation guidance
- Network segmentation strategies
- Privileged access management (PAM)

### Compliance & Best Practices
- Proper log retention considerations
- Data classification awareness
- Chain of custody for forensics
- Professional report formatting

## 🚀 Future Enhancements

Potential extensions to demonstrate additional skills:
- Machine learning for anomaly detection
- Integration with threat intelligence feeds
- Automated response actions (SOAR)
- Dashboard visualization (Grafana/Kibana)
- Multi-threaded processing for performance
- Database backend for historical analysis

## 📞 Contact & Portfolio

This project is part of my security engineering portfolio demonstrating:
- Hands-on SOC analyst experience
- Detection engineering capabilities
- Python development skills
- Incident response expertise
- Technical writing proficiency

**Project Repository**: [Include your GitHub link]  
**LinkedIn**: [Include your LinkedIn]  
**Portfolio**: [Include your portfolio site]

---

## 💡 Why This Project Matters

In today's threat landscape, organizations need SOC analysts who can:
1. **Detect threats quickly** - My Sigma rules catch attacks in real-time
2. **Investigate efficiently** - My Python tools automate tedious analysis
3. **Communicate clearly** - My reports inform both technical and executive audiences
4. **Recommend solutions** - My remediation guidance is actionable and prioritized

This project proves I can deliver all four.

---

*Created as a portfolio demonstration of SOC analyst and security engineering capabilities.*
