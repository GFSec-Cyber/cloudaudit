import boto3
from datetime import datetime, timezone
from utils.scoring import finding

def audit(session):
    findings = []
    iam = session.client('iam')

    # Check root account
    try:
        summary = iam.get_account_summary()['SummaryMap']

        if summary.get('AccountMFAEnabled', 0) == 0:
            findings.append(finding(
                severity="Critical",
                service="IAM",
                resource="root account",
                title="Root Account Has No MFA",
                description="The root account does not have MFA enabled. If the root password is compromised, the entire AWS account is at risk.",
                remediation="Enable MFA on the root account immediately using a hardware key or authenticator app."
            ))

        if summary.get('AccountAccessKeysPresent', 0) > 0:
            findings.append(finding(
                severity="Critical",
                service="IAM",
                resource="root account",
                title="Root Account Has Active Access Keys",
                description="The root account has active access keys. Root access keys provide unrestricted access to all AWS services and should never exist.",
                remediation="Delete all root account access keys immediately. Use IAM users with least-privilege permissions instead."
            ))
    except Exception:
        pass

    # Check IAM users
    try:
        users = iam.list_users()['Users']

        for user in users:
            username = user['UserName']

            # Check MFA
            mfa_devices = iam.list_mfa_devices(UserName=username)['MFADevices']
            if not mfa_devices:
                findings.append(finding(
                    severity="High",
                    service="IAM",
                    resource=username,
                    title="IAM User Has No MFA",
                    description=f"User '{username}' does not have MFA enabled. Password-only accounts are vulnerable to credential stuffing attacks.",
                    remediation=f"Enable MFA for user '{username}' using an authenticator app or hardware key."
                ))

            # Check access key age
            access_keys = iam.list_access_keys(UserName=username)['AccessKeyMetadata']
            for key in access_keys:
                if key['Status'] == 'Active':
                    age = (datetime.now(timezone.utc) - key['CreateDate']).days
                    if age > 90:
                        findings.append(finding(
                            severity="Medium",
                            service="IAM",
                            resource=username,
                            title="Access Key Not Rotated in 90+ Days",
                            description=f"User '{username}' has an access key that is {age} days old. Long-lived credentials increase the risk of compromise.",
                            remediation=f"Rotate the access key for '{username}'. AWS recommends rotating keys every 90 days."
                        ))

            # Check last login
            try:
                iam.get_login_profile(UserName=username)
                last_used = user.get('PasswordLastUsed')
                if last_used:
                    days_inactive = (datetime.now(timezone.utc) - last_used).days
                    if days_inactive > 90:
                        findings.append(finding(
                            severity="Medium",
                            service="IAM",
                            resource=username,
                            title="IAM User Inactive for 90+ Days",
                            description=f"User '{username}' has not logged in for {days_inactive} days. Inactive accounts are an unnecessary attack surface.",
                            remediation=f"Disable or delete IAM user '{username}' if no longer needed."
                        ))
            except iam.exceptions.NoSuchEntityException:
                pass

    except Exception:
        pass

    # Check password policy
    try:
        iam.get_account_password_policy()
    except iam.exceptions.NoSuchEntityException:
        findings.append(finding(
            severity="High",
            service="IAM",
            resource="account password policy",
            title="No IAM Password Policy Configured",
            description="No account-wide password policy is set. Users can create weak passwords with no complexity requirements.",
            remediation="Configure a password policy requiring minimum 14 characters, uppercase, lowercase, numbers, and symbols."
        ))
    except Exception:
        pass

    return findings