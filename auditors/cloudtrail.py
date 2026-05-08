from botocore.exceptions import ClientError
from utils.scoring import finding

def audit(session):
    findings = []
    cloudtrail = session.client("cloudtrail")

    findings += _check_trails(cloudtrail)

    return findings


def _check_trails(cloudtrail):
    findings = []
    try:
        trails = cloudtrail.describe_trails(includeShadowTrails=False)["trailList"]

        if not trails:
            findings.append(finding(
                severity="Critical",
                service="CloudTrail",
                resource="account",
                title="CloudTrail Is Not Enabled",
                description="No CloudTrail trails exist in this account. Every API call goes unlogged — there is no audit trail, no forensics capability, and no incident response visibility.",
                remediation="Enable CloudTrail immediately. Create a trail that applies to all regions and stores logs in a dedicated S3 bucket."
            ))
            return findings

        for trail in trails:
            name = trail["Name"]
            trail_arn = trail["TrailARN"]

            # Check if logging is actually active
            try:
                status = cloudtrail.get_trail_status(Name=trail_arn)
                if not status.get("IsLogging", False):
                    findings.append(finding(
                        severity="Critical",
                        service="CloudTrail",
                        resource=name,
                        title="CloudTrail Trail Is Not Logging",
                        description=f"Trail '{name}' exists but logging is turned off. API calls are not being recorded.",
                        remediation=f"Enable logging on trail '{name}' via the console or: aws cloudtrail start-logging --name {name}"
                    ))
            except ClientError:
                pass

            # Check multi-region
            if not trail.get("IsMultiRegionTrail", False):
                findings.append(finding(
                    severity="High",
                    service="CloudTrail",
                    resource=name,
                    title="CloudTrail Not Configured for All Regions",
                    description=f"Trail '{name}' only covers a single region. API activity in other regions is not logged.",
                    remediation=f"Update trail '{name}' to apply to all regions so no activity goes unrecorded."
                ))

            # Check log file validation
            if not trail.get("LogFileValidationEnabled", False):
                findings.append(finding(
                    severity="Medium",
                    service="CloudTrail",
                    resource=name,
                    title="CloudTrail Log File Validation Disabled",
                    description=f"Trail '{name}' does not have log file validation enabled. Tampered or deleted logs cannot be detected.",
                    remediation=f"Enable log file validation on trail '{name}'. This creates a digest file that proves log integrity."
                ))

            # Check logs are encrypted
            if not trail.get("KMSKeyId"):
                findings.append(finding(
                    severity="Medium",
                    service="CloudTrail",
                    resource=name,
                    title="CloudTrail Logs Not Encrypted with KMS",
                    description=f"Trail '{name}' is not encrypting logs with a KMS key. Logs are stored in S3 with default encryption only.",
                    remediation=f"Configure a KMS key for trail '{name}' to encrypt log files at rest with customer-managed keys."
                ))

    except ClientError as e:
        findings.append(finding(
            severity="High",
            service="CloudTrail",
            resource="cloudtrail",
            title="Could Not Retrieve CloudTrail Trails",
            description=f"CloudAudit was unable to query CloudTrail: {e}",
            remediation="Check IAM permissions for cloudtrail:DescribeTrails."
        ))

    return findings