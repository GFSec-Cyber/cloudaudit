import boto3
from utils.scoring import finding

def audit(session):
    findings = []
    s3 = session.client('s3')
    
    try:
        buckets = s3.list_buckets().get('Buckets', [])
    except Exception as e:
        return findings

    for bucket in buckets:
        name = bucket['Name']

        # Check public access block
        try:
            public_access = s3.get_public_access_block(Bucket=name)
            config = public_access['PublicAccessBlockConfiguration']
            if not all([
                config.get('BlockPublicAcls'),
                config.get('IgnorePublicAcls'),
                config.get('BlockPublicPolicy'),
                config.get('RestrictPublicBuckets')
            ]):
                findings.append(finding(
                    severity="Critical",
                    service="S3",
                    resource=name,
                    title="Public Access Not Fully Blocked",
                    description=f"Bucket '{name}' does not have all public access block settings enabled. This could expose data to the internet.",
                    remediation="Enable all four public access block settings: BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, RestrictPublicBuckets."
                ))
        except s3.exceptions.NoSuchPublicAccessBlockConfiguration:
            findings.append(finding(
                severity="Critical",
                service="S3",
                resource=name,
                title="No Public Access Block Configuration",
                description=f"Bucket '{name}' has no public access block configuration set. It may be publicly accessible.",
                remediation="Configure public access block settings on the bucket immediately."
            ))
        except Exception:
            pass

        # Check encryption
        try:
            s3.get_bucket_encryption(Bucket=name)
        except Exception:
            findings.append(finding(
                severity="High",
                service="S3",
                resource=name,
                title="Bucket Encryption Not Enabled",
                description=f"Bucket '{name}' does not have default server-side encryption enabled. Data at rest is not encrypted.",
                remediation="Enable default encryption using AES-256 or AWS KMS."
            ))

        # Check logging
        try:
            logging = s3.get_bucket_logging(Bucket=name)
            if 'LoggingEnabled' not in logging:
                findings.append(finding(
                    severity="Medium",
                    service="S3",
                    resource=name,
                    title="Bucket Access Logging Disabled",
                    description=f"Bucket '{name}' does not have access logging enabled. You cannot audit who is accessing this bucket.",
                    remediation="Enable server access logging to track requests made to the bucket."
                ))
        except Exception:
            pass

        # Check versioning
        try:
            versioning = s3.get_bucket_versioning(Bucket=name)
            if versioning.get('Status') != 'Enabled':
                findings.append(finding(
                    severity="Low",
                    service="S3",
                    resource=name,
                    title="Bucket Versioning Not Enabled",
                    description=f"Bucket '{name}' does not have versioning enabled. Deleted or overwritten files cannot be recovered.",
                    remediation="Enable versioning to protect against accidental deletion or overwrites."
                ))
        except Exception:
            pass

    return findings