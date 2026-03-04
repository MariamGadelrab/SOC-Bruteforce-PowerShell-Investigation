#!/usr/bin/env python3
"""
SOC Mini-Engagement Investigation Script
Analyzes Windows Security and PowerShell logs for brute force attacks and suspicious PowerShell activity.
"""

import argparse
import sys
from pathlib import Path
import pandas as pd
from datetime import datetime
from utils import (
    detect_brute_force,
    detect_suspicious_powershell,
    calculate_severity,
    generate_timeline
)


def main():
    parser = argparse.ArgumentParser(
        description='Investigate Windows logs for security incidents',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python investigate.py --input data/logs.csv --out output/
  python investigate.py -i data/logs.csv -o output/
        """
    )
    parser.add_argument(
        '--input', '-i',
        required=True,
        help='Path to input CSV log file'
    )
    parser.add_argument(
        '--out', '-o',
        required=True,
        help='Output directory for investigation results'
    )
    
    args = parser.parse_args()
    
    # Validate input file
    input_path = Path(args.input)
    if not input_path.exists():
        print(f"[ERROR] Input file not found: {args.input}")
        sys.exit(1)
    
    # Create output directory
    output_dir = Path(args.out)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    print(f"[*] Loading logs from: {args.input}")
    
    try:
        # Load logs with proper timestamp parsing
        df = pd.read_csv(
            input_path,
            parse_dates=['timestamp_utc'],
            date_format='ISO8601'
        )
        print(f"[+] Loaded {len(df)} log entries")
        
    except Exception as e:
        print(f"[ERROR] Failed to load logs: {e}")
        sys.exit(1)
    
    # Run detections
    print("\n[*] Running brute force detection...")
    brute_force_hits = detect_brute_force(df)
    print(f"[+] Found {len(brute_force_hits)} brute force incidents")
    
    print("\n[*] Running suspicious PowerShell detection...")
    powershell_hits = detect_suspicious_powershell(df)
    print(f"[+] Found {len(powershell_hits)} suspicious PowerShell events")
    
    # Generate timeline
    print("\n[*] Generating timeline...")
    timeline = generate_timeline(df, brute_force_hits, powershell_hits)
    
    # Create findings summary
    print("\n[*] Creating findings summary...")
    findings = []
    
    # Summarize brute force findings
    if not brute_force_hits.empty:
        for _, group in brute_force_hits.groupby(['host', 'source_ip']):
            finding = {
                'finding_type': 'Brute Force Attack',
                'host': group.iloc[0]['host'],
                'user': group.iloc[0]['user'],
                'source_ip': group.iloc[0]['source_ip'],
                'failed_attempts': len(group[group['event_id'] == 4625]),
                'success': 'Yes' if any(group['event_id'] == 4624) else 'No',
                'first_seen': group['timestamp_utc'].min(),
                'last_seen': group['timestamp_utc'].max(),
                'severity': calculate_severity('brute_force', len(group[group['event_id'] == 4625]))
            }
            findings.append(finding)
    
    # Summarize PowerShell findings
    if not powershell_hits.empty:
        for idx, row in powershell_hits.iterrows():
            finding = {
                'finding_type': 'Suspicious PowerShell',
                'host': row['host'],
                'user': row['user'],
                'source_ip': row.get('source_ip', 'N/A'),
                'command_snippet': row['command_line'][:100] + '...' if len(row['command_line']) > 100 else row['command_line'],
                'indicators': row['indicators'],
                'first_seen': row['timestamp_utc'],
                'last_seen': row['timestamp_utc'],
                'severity': calculate_severity('powershell', row['risk_score'])
            }
            findings.append(finding)
    
    findings_df = pd.DataFrame(findings)
    
    # Save outputs
    print("\n[*] Saving results...")
    
    findings_df.to_csv(output_dir / 'findings_summary.csv', index=False)
    print(f"[+] Saved: {output_dir / 'findings_summary.csv'}")
    
    brute_force_hits.to_csv(output_dir / 'brute_force_hits.csv', index=False)
    print(f"[+] Saved: {output_dir / 'brute_force_hits.csv'}")
    
    powershell_hits.to_csv(output_dir / 'powershell_hits.csv', index=False)
    print(f"[+] Saved: {output_dir / 'powershell_hits.csv'}")
    
    timeline.to_csv(output_dir / 'timeline.csv', index=False)
    print(f"[+] Saved: {output_dir / 'timeline.csv'}")
    
    # Print summary
    print("\n" + "="*60)
    print("INVESTIGATION SUMMARY")
    print("="*60)
    print(f"Total Events Analyzed: {len(df)}")
    print(f"Brute Force Incidents: {len(brute_force_hits.groupby(['host', 'source_ip']))}")
    print(f"Suspicious PowerShell Events: {len(powershell_hits)}")
    print(f"\nSeverity Breakdown:")
    if not findings_df.empty:
        severity_counts = findings_df['severity'].value_counts()
        for severity in ['High', 'Medium', 'Low']:
            count = severity_counts.get(severity, 0)
            print(f"  {severity}: {count}")
    print("="*60)
    print(f"\n[+] Investigation complete! Results saved to: {output_dir}")


if __name__ == '__main__':
    main()
