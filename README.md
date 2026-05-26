# AWS Security Hub Custom Insights Aggregator

[![Language](https://img.shields.io/badge/Language-Python%203.9%2B-blue.svg)](https://www.python.org/)
[![SDK](https://img.shields.io/badge/SDK-Boto3-orange.svg)](https://aws.amazon.com/pythonsdk/)
[![Management](https://img.shields.io/badge/Dashboard-Executive%20Reporting-blue.svg)](https://aws.amazon.com/security-hub/)

## Operational Overview

This repository contains a high-utility Python reporting engine that programmatically queries **AWS Security Hub** to aggregate, filter, and compile critical compliance vulnerabilities across an enterprise cloud multi-account structure.

Security Hub consolidates data from GuardDuty, Inspector, and Macie, but the native UI console causes alert fatigue. This automation solution queries active findings, aggregates them by severity scoring (CRITICAL/HIGH), isolates architectural compliance failures, and exports an executive metrics matrix summary to accelerate patch windows.

---

###  Core Security Controls Managed

* **Severity Consolidation Tiering:** Filters active, un-resolved findings to pull out only `CRITICAL` and `HIGH` security alerts requiring immediate response engineering.
* **Regulatory Compliance Ingestion:** Groups distributed vulnerabilities by specific compliance standard controls (such as AWS Foundational Security Best Practices, CIS Benchmarks).
* **Automated JSON/Executive Ledger Export:** Generates clean structured telemetry streams ideal for automated Slack alerts, Jira ticket provisioning, or compliance review boards.

---

## Repository Structural Mapping

```text
aws-securityhub-insight-aggregator/
├── README.md                      # Executive summary and structural breakdown
├── securityhub_aggregator.py      # Core data-gathering Python engine
├── requirements.txt               # Script dependencies
└── security_hub_summary.json      # Structured dashboard output asset
