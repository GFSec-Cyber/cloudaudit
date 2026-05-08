SEVERITY_ORDER = ["Critical", "High", "Medium", "Low"]

SEVERITY_COLORS = {
    "Critical": "bold red",
    "High": "yellow",
    "Medium": "cyan",
    "Low": "dim white"
}

def finding(severity, service, resource, title, description, remediation):
    return {
        "severity": severity,
        "service": service,
        "resource": resource,
        "title": title,
        "description": description,
        "remediation": remediation
    }

def sort_findings(findings):
    return sorted(findings, key=lambda x: SEVERITY_ORDER.index(x["severity"]))