### 2. `securityhub_aggregator.py`
```python
#!/usr/bin/env python3
"""
AWS Security Hub Custom Insights Aggregator
Queries live Security Hub findings to aggregate critical and high alerts into an executive dashboard ledger.
"""

import boto3
import json
from datetime import datetime, timezone

def main():
    print("[+] Connecting to AWS Security Hub Data Plane...")
    sh_client = boto3.client('securityhub')
    
    # Establish strict filters: Active findings, Severity >= HIGH, Workflow Status != RESOLVED
    finding_filters = {
        'ComplianceStatus': [{'Value': 'FAILED', 'Comparison': 'EQUALS'}],
        'SeverityLabel': [
            {'Value': 'CRITICAL', 'Comparison': 'EQUALS'},
            {'Value': 'HIGH', 'Comparison': 'EQUALS'}
        ],
        'RecordState': [{'Value': 'ACTIVE', 'Comparison': 'EQUALS'}],
        'WorkflowStatus': [{'Value': 'RESOLVED', 'Comparison': 'NOT_EQUALS'}]
    }
    
    print("[+] Extracting raw compliance findings matrix...")
    try:
        response = sh_client.get_findings(Filters=finding_filters, MaxResults=50)
        findings_list = response.get('Findings', [])
    except Exception as e:
        print(f"[-] Security Hub query halted: {str(e)}")
        print("[!] Ensure AWS Security Hub is fully enabled in this region.")
        return

    executive_summary = []
    
    for finding in findings_list:
        summary_block = {
            "FindingId": finding.get('Id'),
            "Title": finding.get('Title'),
            "Description": finding.get('Description'),
            "CompanyControlId": finding.get('Compliance', {}).get('SecurityControlId', 'N/A'),
            "Severity": finding.get('Severity', {}).get('Label'),
            "AwsAccountId": finding.get('AwsAccountId'),
            "RemediationRecommendation": finding.get('Remediation', {}).get('Recommendation', {}).get('Text', 'No data provided.')
        }
        executive_summary.append(summary_block)

    # Compile unified diagnostic payload
    dashboard_payload = {
        "AggregationTimestamp": datetime.now(timezone.utc).isoformat(),
        "TotalCriticalHighViolations": len(executive_summary),
        "VulnerabilitiesDashboard": executive_summary
    }
    
    with open('security_hub_summary.json', 'w') as f:
        json.dump(dashboard_payload, f, indent=4)
    print(f"[+] Metrics compiled successfully. Aggregated {len(executive_summary)} high-severity findings.")

if __name__ == '__main__':
    main()
