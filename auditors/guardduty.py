from botocore.exceptions import ClientError
from utils.scoring import finding

def audit(session):
    findings = []
    guardduty = session.client("guardduty")

    findings += _check_guardduty(guardduty)

    return findings


def _check_guardduty(guardduty):
    findings = []
    try:
        detectors = guardduty.list_detectors()["DetectorIds"]

        if not detectors:
            findings.append(finding(
                severity="High",
                service="GuardDuty",
                resource="account",
                title="GuardDuty Is Not Enabled",
                description="GuardDuty is not enabled in this account. AWS's built-in threat detection is completely off — malicious activity, compromised credentials, and reconnaissance attempts will go undetected.",
                remediation="Enable GuardDuty in all regions. It takes one click and costs very little for small accounts."
            ))
            return findings

        for detector_id in detectors:
            detector = guardduty.get_detector(DetectorId=detector_id)

            if detector.get("Status") != "ENABLED":
                findings.append(finding(
                    severity="High",
                    service="GuardDuty",
                    resource=detector_id,
                    title="GuardDuty Detector Is Disabled",
                    description=f"GuardDuty detector '{detector_id}' exists but is not enabled. Threat detection is inactive.",
                    remediation=f"Enable the GuardDuty detector '{detector_id}' via the console or CLI."
                ))

    except ClientError as e:
        findings.append(finding(
            severity="High",
            service="GuardDuty",
            resource="guardduty",
            title="Could Not Retrieve GuardDuty Status",
            description=f"CloudAudit was unable to query GuardDuty: {e}",
            remediation="Check IAM permissions for guardduty:ListDetectors."
        ))

    return findings