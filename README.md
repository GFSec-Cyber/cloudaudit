# ☁ CloudAudit

> AWS Security Misconfiguration Scanner — audit your entire AWS account in under 60 seconds.

CloudAudit connects to your AWS account, audits it for the most dangerous security misconfigurations across 6 services, scores every finding by severity, and generates a clean HTML report with remediation guidance.

![Python](https://img.shields.io/badge/Python-3.8+-blue?style=flat-square)
![AWS](https://img.shields.io/badge/AWS-Boto3-orange?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)

## Screenshots

<img width="700" height="554" alt="cli" src="https://github.com/user-attachments/assets/50087f3f-0826-4cde-8e37-d64fa571b39c" />

<img width="1071" height="108" alt="summary" src="https://github.com/user-attachments/assets/1700cdb6-4af1-4107-be28-0f6274238184" />

<img width="1099" height="911" alt="report" src="https://github.com/user-attachments/assets/9504d4bd-d6d1-46f5-a7d0-968befb52605" />


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
