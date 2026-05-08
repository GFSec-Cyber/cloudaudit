from botocore.exceptions import ClientError
from utils.scoring import finding

DANGEROUS_PORTS = {
    22: "SSH",
    3389: "RDP",
    3306: "MySQL",
    5432: "PostgreSQL",
    1433: "MSSQL",
    27017: "MongoDB",
    6379: "Redis",
    9200: "Elasticsearch",
}

def audit(session):
    findings = []
    ec2 = session.client("ec2")

    findings += _check_security_groups(ec2)
    findings += _check_ebs_volumes(ec2)
    findings += _check_public_instances(ec2)

    return findings


def _check_security_groups(ec2):
    findings = []
    try:
        paginator = ec2.get_paginator("describe_security_groups")
        for page in paginator.paginate():
            for sg in page["SecurityGroups"]:
                sg_id = sg["GroupId"]
                sg_name = sg.get("GroupName", "unnamed")

                for rule in sg.get("IpPermissions", []):
                    from_port = rule.get("FromPort", 0)
                    to_port = rule.get("ToPort", 65535)
                    protocol = rule.get("IpProtocol", "-1")

                    open_to_world = any(
                        r.get("CidrIp") == "0.0.0.0/0"
                        for r in rule.get("IpRanges", [])
                    ) or any(
                        r.get("CidrIpv6") == "::/0"
                        for r in rule.get("Ipv6Ranges", [])
                    )

                    if not open_to_world:
                        continue

                    if protocol == "-1":
                        findings.append(finding(
                            severity="Critical",
                            service="EC2",
                            resource=f"{sg_id} ({sg_name})",
                            title="Security Group Allows All Traffic from 0.0.0.0/0",
                            description=f"Security group '{sg_name}' ({sg_id}) has an inbound rule permitting all traffic from any IP. Every port on every instance using this group is reachable from the internet.",
                            remediation="Remove the all-traffic inbound rule. Restrict to specific ports and trusted IP ranges only."
                        ))
                        continue

                    for port, service_name in DANGEROUS_PORTS.items():
                        if from_port <= port <= to_port:
                            severity = "Critical" if port in (22, 3389) else "High"
                            findings.append(finding(
                                severity=severity,
                                service="EC2",
                                resource=f"{sg_id} ({sg_name})",
                                title=f"Port {port} ({service_name}) Open to 0.0.0.0/0",
                                description=f"Security group '{sg_name}' ({sg_id}) allows inbound {service_name} traffic on port {port} from any IP address. This exposes the service directly to the internet.",
                                remediation=f"Restrict port {port} to known IP ranges. For SSH/RDP, use a bastion host or VPN. For databases, never expose to the internet."
                            ))

    except ClientError as e:
        findings.append(finding(
            severity="High",
            service="EC2",
            resource="security-groups",
            title="Could Not Retrieve Security Groups",
            description=f"CloudAudit was unable to list security groups: {e}",
            remediation="Check IAM permissions for ec2:DescribeSecurityGroups."
        ))

    return findings


def _check_ebs_volumes(ec2):
    findings = []
    try:
        paginator = ec2.get_paginator("describe_volumes")
        for page in paginator.paginate():
            for volume in page["Volumes"]:
                vol_id = volume["VolumeId"]
                if not volume.get("Encrypted", False):
                    findings.append(finding(
                        severity="High",
                        service="EC2",
                        resource=vol_id,
                        title="EBS Volume Not Encrypted",
                        description=f"EBS volume '{vol_id}' is not encrypted. If the volume is detached or a snapshot is shared, data is exposed in plaintext.",
                        remediation="Enable EBS encryption by default in account settings. For existing volumes, create an encrypted snapshot and restore from it."
                    ))

    except ClientError as e:
        findings.append(finding(
            severity="High",
            service="EC2",
            resource="ebs-volumes",
            title="Could Not Retrieve EBS Volumes",
            description=f"CloudAudit was unable to list EBS volumes: {e}",
            remediation="Check IAM permissions for ec2:DescribeVolumes."
        ))

    return findings


def _check_public_instances(ec2):
    findings = []
    try:
        paginator = ec2.get_paginator("describe_instances")
        for page in paginator.paginate():
            for reservation in page["Reservations"]:
                for instance in reservation["Instances"]:
                    if instance["State"]["Name"] != "running":
                        continue

                    instance_id = instance["InstanceId"]
                    public_ip = instance.get("PublicIpAddress")

                    if public_ip:
                        name = next(
                            (t["Value"] for t in instance.get("Tags", []) if t["Key"] == "Name"),
                            "unnamed"
                        )
                        findings.append(finding(
                            severity="Medium",
                            service="EC2",
                            resource=f"{instance_id} ({name})",
                            title="EC2 Instance Has Public IP Address",
                            description=f"Instance '{name}' ({instance_id}) is assigned a public IP ({public_ip}). Direct public exposure increases the attack surface.",
                            remediation="Use a load balancer or NAT gateway instead of direct public IPs. Only intentional internet-facing resources should have public IPs."
                        ))

    except ClientError as e:
        findings.append(finding(
            severity="High",
            service="EC2",
            resource="instances",
            title="Could Not Retrieve EC2 Instances",
            description=f"CloudAudit was unable to list EC2 instances: {e}",
            remediation="Check IAM permissions for ec2:DescribeInstances."
        ))

    return findings