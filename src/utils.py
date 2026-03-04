"""
Utility functions for log analysis and detection logic.
"""

import pandas as pd
import base64
from datetime import timedelta


def detect_brute_force(df, threshold=5, time_window_minutes=5):
    """
    Detect brute force attacks by identifying multiple failed logons from the same source IP
    followed by a successful logon within a time window.
    
    Args:
        df: DataFrame containing log data
        threshold: Minimum number of failed attempts to trigger detection
        time_window_minutes: Time window in minutes to group events
    
    Returns:
        DataFrame containing brute force attack events
    """
    # Filter for logon events (4624 success, 4625 failure)
    logon_events = df[df['event_id'].isin([4624, 4625])].copy()
    
    if logon_events.empty:
        return pd.DataFrame()
    
    # Sort by timestamp
    logon_events = logon_events.sort_values('timestamp_utc')
    
    brute_force_hits = []
    
    # Group by host and source_ip
    for (host, source_ip), group in logon_events.groupby(['host', 'source_ip']):
        if pd.isna(source_ip):
            continue
            
        group = group.sort_values('timestamp_utc')
        
        # Sliding window approach
        for i in range(len(group)):
            window_start = group.iloc[i]['timestamp_utc']
            window_end = window_start + timedelta(minutes=time_window_minutes)
            
            # Get events within window
            window_events = group[
                (group['timestamp_utc'] >= window_start) & 
                (group['timestamp_utc'] <= window_end)
            ]
            
            # Count failures and check for success
            failures = window_events[window_events['event_id'] == 4625]
            successes = window_events[window_events['event_id'] == 4624]
            
            # Detection logic: threshold failures followed by success
            if len(failures) >= threshold and len(successes) > 0:
                # Add all events in this window to hits
                for _, event in window_events.iterrows():
                    brute_force_hits.append(event)
                break  # Move to next group
    
    if brute_force_hits:
        return pd.DataFrame(brute_force_hits).drop_duplicates()
    return pd.DataFrame()


def detect_suspicious_powershell(df):
    """
    Detect suspicious PowerShell activity based on command line indicators.
    
    Indicators include:
    - Encoded commands (-EncodedCommand, -enc)
    - Download cradles (DownloadString, WebClient, IWR)
    - Execution policy bypass
    - Hidden window execution
    - Invoke-Expression (IEX)
    
    Args:
        df: DataFrame containing log data
    
    Returns:
        DataFrame containing suspicious PowerShell events with risk scores
    """
    # Filter for PowerShell events
    ps_events = df[
        (df['log_channel'] == 'PowerShell') | 
        (df['process_name'] == 'powershell.exe')
    ].copy()
    
    if ps_events.empty:
        return pd.DataFrame()
    
    suspicious_hits = []
    
    for idx, row in ps_events.iterrows():
        command_line = str(row.get('command_line', '')).lower()
        
        if not command_line or command_line == 'nan':
            continue
        
        indicators = []
        risk_score = 0
        
        # Check for encoded commands
        if any(enc in command_line for enc in ['-encodedcommand', '-enc', '-e ', 'frombase64string']):
            indicators.append('Encoded Command')
            risk_score += 30
            
            # Try to decode if possible
            try:
                if 'encodedcommand' in command_line:
                    encoded_part = command_line.split('encodedcommand')[1].split()[0]
                    decoded = base64.b64decode(encoded_part).decode('utf-16-le', errors='ignore')
                    if any(mal in decoded.lower() for mal in ['downloadstring', 'webclient', 'iex']):
                        risk_score += 20
            except:
                pass
        
        # Check for download cradles
        download_indicators = ['downloadstring', 'downloadfile', 'webclient', 'invoke-webrequest', 'iwr', 'wget', 'curl']
        if any(dl in command_line for dl in download_indicators):
            indicators.append('Download Cradle')
            risk_score += 35
        
        # Check for execution policy bypass
        if any(bypass in command_line for bypass in ['-executionpolicy bypass', '-ep bypass', '-exec bypass']):
            indicators.append('Execution Policy Bypass')
            risk_score += 15
        
        # Check for hidden window
        if any(hidden in command_line for hidden in ['-windowstyle hidden', '-w hidden']):
            indicators.append('Hidden Window')
            risk_score += 20
        
        # Check for no profile
        if '-noprofile' in command_line:
            indicators.append('No Profile')
            risk_score += 10
        
        # Check for Invoke-Expression
        if any(iex in command_line for iex in ['iex', 'invoke-expression']):
            indicators.append('Invoke-Expression')
            risk_score += 25
        
        # If any indicators found, add to suspicious hits
        if indicators:
            row_dict = row.to_dict()
            row_dict['indicators'] = ', '.join(indicators)
            row_dict['risk_score'] = risk_score
            suspicious_hits.append(row_dict)
    
    if suspicious_hits:
        return pd.DataFrame(suspicious_hits)
    return pd.DataFrame()


def calculate_severity(finding_type, metric):
    """
    Calculate severity level based on finding type and associated metric.
    
    Args:
        finding_type: Type of finding ('brute_force' or 'powershell')
        metric: Numeric metric (failed attempts for brute force, risk score for PowerShell)
    
    Returns:
        Severity level: 'Low', 'Medium', or 'High'
    """
    if finding_type == 'brute_force':
        # Based on number of failed attempts
        if metric >= 10:
            return 'High'
        elif metric >= 5:
            return 'Medium'
        else:
            return 'Low'
    
    elif finding_type == 'powershell':
        # Based on risk score
        if metric >= 60:
            return 'High'
        elif metric >= 30:
            return 'Medium'
        else:
            return 'Low'
    
    return 'Low'


def generate_timeline(df, brute_force_hits, powershell_hits):
    """
    Generate a chronological timeline of all relevant security events.
    
    Args:
        df: Original DataFrame with all logs
        brute_force_hits: DataFrame with brute force detections
        powershell_hits: DataFrame with PowerShell detections
    
    Returns:
        DataFrame with timeline of events including detection flags
    """
    timeline = df.copy()
    timeline['detection_type'] = 'None'
    timeline['severity'] = 'Info'
    
    # Mark brute force events
    if not brute_force_hits.empty:
        for idx, row in brute_force_hits.iterrows():
            mask = (
                (timeline['timestamp_utc'] == row['timestamp_utc']) &
                (timeline['host'] == row['host']) &
                (timeline['event_id'] == row['event_id'])
            )
            timeline.loc[mask, 'detection_type'] = 'Brute Force'
            timeline.loc[mask, 'severity'] = calculate_severity('brute_force', 5)
    
    # Mark PowerShell events
    if not powershell_hits.empty:
        for idx, row in powershell_hits.iterrows():
            mask = (
                (timeline['timestamp_utc'] == row['timestamp_utc']) &
                (timeline['host'] == row['host']) &
                (timeline['log_channel'] == 'PowerShell')
            )
            timeline.loc[mask, 'detection_type'] = 'Suspicious PowerShell'
            timeline.loc[mask, 'severity'] = calculate_severity('powershell', row['risk_score'])
    
    # Sort by timestamp
    timeline = timeline.sort_values('timestamp_utc')
    
    return timeline
