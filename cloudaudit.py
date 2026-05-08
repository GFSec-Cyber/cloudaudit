import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box
from auditors import get_session
from auditors import s3 as s3_auditor
from utils.scoring import sort_findings, SEVERITY_COLORS
from auditors import iam as iam_auditor
from auditors import ec2 as ec2_auditor
from auditors import cloudtrail as cloudtrail_auditor
from auditors import rds as rds_auditor
from auditors import guardduty as guardduty_auditor
from report import generator

console = Console()

def print_findings(findings, module_name):
    if not findings:
        console.print(f"[bold green]✓ {module_name}[/bold green] — No issues found\n")
        return

    console.print(f"[bold red]✗ {module_name}[/bold red] — {len(findings)} issue(s) found\n")

    for f in findings:
        color = SEVERITY_COLORS.get(f['severity'], 'white')
        console.print(f"  [{color}][{f['severity']}][/{color}] [bold]{f['title']}[/bold]")
        console.print(f"  [dim]Resource:[/dim] {f['resource']}")
        console.print(f"  [dim]Issue:[/dim] {f['description']}")
        console.print(f"  [dim]Fix:[/dim] {f['remediation']}\n")

@click.command()
@click.option('--profile', default='default', help='AWS profile to use')
@click.option('--region', default='us-east-1', help='AWS region to audit')
@click.option('--modules', default='all', help='Comma-separated modules: s3,iam,ec2,cloudtrail,rds,guardduty')
@click.option('--report', is_flag=True, help='Generate HTML report')
def main(profile, region, modules, report):
    """CloudAudit — AWS Security Misconfiguration Scanner"""

    console.print(Panel.fit(
        "[bold cyan]CloudAudit[/bold cyan] — AWS Security Misconfiguration Scanner",
        border_style="cyan"
    ))

    console.print(f"\n[bold]Profile:[/bold] {profile}")
    console.print(f"[bold]Region:[/bold] {region}")
    console.print(f"[bold]Modules:[/bold] {modules}\n")

    # Connect to AWS
    console.print("[yellow]Connecting to AWS...[/yellow]")
    session, identity = get_session(profile, region)

    if session is None:
        console.print(f"[bold red]Connection failed:[/bold red] {identity}")
        return

    console.print(f"[bold green]Connected![/bold green]")
    console.print(f"Account: [cyan]{identity['Account']}[/cyan]")
    console.print(f"User: [cyan]{identity['Arn']}[/cyan]\n")

    all_findings = []
    run_modules = [m.strip() for m in modules.split(',')] if modules != 'all' else ['s3', 'iam', 'ec2', 'cloudtrail', 'rds', 'guardduty']

    # S3
    if 's3' in run_modules:
        console.print("[yellow]Auditing S3...[/yellow]")
        findings = s3_auditor.audit(session)
        all_findings.extend(findings)
        print_findings(sort_findings(findings), "S3")

    # IAM
    if 'iam' in run_modules:
        console.print("[yellow]Auditing IAM...[/yellow]")
        findings = iam_auditor.audit(session)
        all_findings.extend(findings)
        print_findings(sort_findings(findings), "IAM")

    # EC2
    if 'ec2' in run_modules:
        console.print("[yellow]Auditing EC2...[/yellow]")
        findings = ec2_auditor.audit(session)
        all_findings.extend(findings)
        print_findings(sort_findings(findings), "EC2")

    # CloudTrail
    if 'cloudtrail' in run_modules:
        console.print("[yellow]Auditing CloudTrail...[/yellow]")
        findings = cloudtrail_auditor.audit(session)
        all_findings.extend(findings)
        print_findings(sort_findings(findings), "CloudTrail")

    # RDS
    if 'rds' in run_modules:
        console.print("[yellow]Auditing RDS...[/yellow]")
        findings = rds_auditor.audit(session)
        all_findings.extend(findings)
        print_findings(sort_findings(findings), "RDS")

    # GuardDuty
    if 'guardduty' in run_modules:
        console.print("[yellow]Auditing GuardDuty...[/yellow]")
        findings = guardduty_auditor.audit(session)
        all_findings.extend(findings)
        print_findings(sort_findings(findings), "GuardDuty")

    # Summary
    critical = len([f for f in all_findings if f['severity'] == 'Critical'])
    high = len([f for f in all_findings if f['severity'] == 'High'])
    medium = len([f for f in all_findings if f['severity'] == 'Medium'])
    low = len([f for f in all_findings if f['severity'] == 'Low'])

    console.print(Panel(
        f"[bold red]Critical: {critical}[/bold red]  [yellow]High: {high}[/yellow]  [cyan]Medium: {medium}[/cyan]  [dim]Low: {low}[/dim]",
        title="Audit Summary",
        border_style="cyan"
    ))

    if report:
        console.print("\n[yellow]Generating HTML report...[/yellow]")
        path = generator.generate(all_findings, profile, region)
        console.print(f"[bold green]Report saved:[/bold green] {path}\n")

if __name__ == '__main__':
    main()