# ☁ CloudAudit

> AWS Security Misconfiguration Scanner — audit your entire AWS account in under 60 seconds.

CloudAudit connects to your AWS account, audits it for the most dangerous security misconfigurations across 6 services, scores every finding by severity, and generates a clean HTML report with remediation guidance.

![Python](https://img.shields.io/badge/Python-3.8+-blue?style=flat-square)
![AWS](https://img.shields.io/badge/AWS-Boto3-orange?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)

## Screenshots

<img width="1545" height="790" alt="Screenshot 2026-05-07 at 10 55 25 PM" src="https://github.com/user-attachments/assets/3fcb3a9d-cd57-46c2-aeef-1448f96529a7" />

<img width="1095" height="918" alt="Screenshot 2026-05-07 at 10 56 03 PM" src="https://github.com/user-attachments/assets/15c1424d-f516-4e11-8860-7dab948a25fa" />

---

## What It Audits

| Module | Checks |
|---|---|
| **S3** | Public access, encryption, logging, versioning |
| **IAM** | Root access keys, MFA, key rotation, password policy, inactive users |
| **EC2** | Dangerous open ports, unencrypted EBS volumes, public IPs |
| **CloudTrail** | Logging enabled, multi-region, log validation, KMS encryption |
| **RDS** | Public accessibility, storage encryption, automated backups |
| **GuardDuty** | Detector enabled and active |

## Severity Ratings

| Severity | Example |
|---|---|
| 🔴 Critical | Public S3 bucket, open RDP to internet, no CloudTrail |
| 🟠 High | No MFA on IAM users, GuardDuty disabled |
| 🔵 Medium | Access keys not rotated in 90+ days |
| 🟢 Low | Missing versioning, no Multi-AZ on RDS |

---

## Installation

```bash
git clone https://github.com/GFSec-Cyber/cloudaudit.git
cd cloudaudit
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Requirements

- Python 3.8+
- AWS credentials configured (`aws configure` or `~/.aws/credentials`)
- IAM permissions for: `s3`, `iam`, `ec2`, `cloudtrail`, `rds`, `guardduty`

---

## Usage

```bash
# Full audit
python cloudaudit.py --profile default --region us-east-1

# Generate HTML report
python cloudaudit.py --profile default --region us-east-1 --report

# Audit specific modules only
python cloudaudit.py --modules s3,iam,ec2

# Audit a different region
python cloudaudit.py --profile default --region us-west-2
```

## Example Output

```
CloudAudit — AWS Security Misconfiguration Scanner

Auditing IAM...
✗ IAM — 6 issue(s) found

  [Critical] Root Account Has Active Access Keys
  Resource: root account
  Issue: The root account has active access keys...
  Fix: Delete all root account access keys immediately...

Audit Summary
Critical: 3  High: 4  Medium: 2  Low: 0
```

---

## Project Structure

```
cloudaudit/
├── cloudaudit.py          # Main CLI entry point
├── auditors/
│   ├── s3.py              # S3 audit module
│   ├── iam.py             # IAM audit module
│   ├── ec2.py             # EC2 and security groups
│   ├── cloudtrail.py      # CloudTrail audit module
│   ├── rds.py             # RDS audit module
│   └── guardduty.py       # GuardDuty audit module
├── report/
│   ├── generator.py       # HTML report generator
│   └── template.html      # Report template
├── utils/
│   └── scoring.py         # Severity scoring logic
├── requirements.txt
└── README.md
```

---

## IAM Permissions Required

CloudAudit needs read-only access. Attach this policy to your IAM user:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:ListAllMyBuckets",
        "s3:GetBucketPublicAccessBlock",
        "s3:GetBucketEncryption",
        "s3:GetBucketLogging",
        "s3:GetBucketVersioning",
        "iam:GetAccountSummary",
        "iam:ListUsers",
        "iam:ListMFADevices",
        "iam:ListAccessKeys",
        "iam:GetLoginProfile",
        "iam:GetAccountPasswordPolicy",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeVolumes",
        "ec2:DescribeInstances",
        "cloudtrail:DescribeTrails",
        "cloudtrail:GetTrailStatus",
        "rds:DescribeDBInstances",
        "guardduty:ListDetectors",
        "guardduty:GetDetector"
      ],
      "Resource": "*"
    }
  ]
}
```

---

## Built With

- [Boto3](https://boto3.amazonaws.com/v1/documentation/api/latest/index.html) — AWS SDK for Python
- [Click](https://click.palletsprojects.com/) — CLI framework
- [Rich](https://github.com/Textualize/rich) — Terminal formatting
- [Jinja2](https://jinja.palletsprojects.com/) — HTML report templating

---

## Author

Built by Garrett — cybersecurity professional and CompTIA Security+ certified.
