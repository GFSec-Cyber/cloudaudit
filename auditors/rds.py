from botocore.exceptions import ClientError
from utils.scoring import finding

def audit(session):
    findings = []
    rds = session.client("rds")

    findings += _check_rds_instances(rds)

    return findings


def _check_rds_instances(rds):
    findings = []
    try:
        paginator = rds.get_paginator("describe_db_instances")
        for page in paginator.paginate():
            for db in page["DBInstances"]:
                db_id = db["DBInstanceIdentifier"]
                engine = db["Engine"]

                # Check public accessibility
                if db.get("PubliclyAccessible", False):
                    findings.append(finding(
                        severity="Critical",
                        service="RDS",
                        resource=db_id,
                        title="RDS Instance Is Publicly Accessible",
                        description=f"Database '{db_id}' ({engine}) is configured as publicly accessible. Databases should never be directly reachable from the internet.",
                        remediation=f"Disable public accessibility on '{db_id}'. Place RDS instances in a private subnet and access them only through application servers or a bastion host."
                    ))

                # Check encryption
                if not db.get("StorageEncrypted", False):
                    findings.append(finding(
                        severity="High",
                        service="RDS",
                        resource=db_id,
                        title="RDS Instance Storage Not Encrypted",
                        description=f"Database '{db_id}' ({engine}) does not have storage encryption enabled. Data at rest is stored in plaintext.",
                        remediation=f"Enable storage encryption on '{db_id}'. Note: encryption must be set at creation time. To encrypt an existing instance, take a snapshot, copy it with encryption enabled, and restore."
                    ))

                # Check automated backups
                if db.get("BackupRetentionPeriod", 0) == 0:
                    findings.append(finding(
                        severity="Medium",
                        service="RDS",
                        resource=db_id,
                        title="RDS Automated Backups Disabled",
                        description=f"Database '{db_id}' ({engine}) has automated backups disabled. A failure or corruption event would result in permanent data loss.",
                        remediation=f"Enable automated backups on '{db_id}' with a retention period of at least 7 days."
                    ))

                # Check multi-AZ
                if not db.get("MultiAZ", False):
                    findings.append(finding(
                        severity="Low",
                        service="RDS",
                        resource=db_id,
                        title="RDS Instance Not Multi-AZ",
                        description=f"Database '{db_id}' ({engine}) is not configured for Multi-AZ deployment. A single AZ failure would cause downtime.",
                        remediation=f"Enable Multi-AZ on '{db_id}' for automatic failover and high availability."
                    ))

    except ClientError as e:
        findings.append(finding(
            severity="High",
            service="RDS",
            resource="rds",
            title="Could Not Retrieve RDS Instances",
            description=f"CloudAudit was unable to query RDS: {e}",
            remediation="Check IAM permissions for rds:DescribeDBInstances."
        ))

    return findings