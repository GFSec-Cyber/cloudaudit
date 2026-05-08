from jinja2 import Environment, FileSystemLoader
from datetime import datetime
import os

def generate(all_findings, profile, region):
    template_dir = os.path.join(os.path.dirname(__file__))
    env = Environment(loader=FileSystemLoader(template_dir))
    template = env.get_template("template.html")

    critical = [f for f in all_findings if f['severity'] == 'Critical']
    high = [f for f in all_findings if f['severity'] == 'High']
    medium = [f for f in all_findings if f['severity'] == 'Medium']
    low = [f for f in all_findings if f['severity'] == 'Low']

    html = template.render(
        generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        profile=profile,
        region=region,
        all_findings=all_findings,
        critical=critical,
        high=high,
        medium=medium,
        low=low,
        total=len(all_findings)
    )

    output_path = "cloudaudit_report.html"
    with open(output_path, "w") as f:
        f.write(html)

    return output_path