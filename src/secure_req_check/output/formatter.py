import json
import csv
import io
from typing import List
from tabulate import tabulate
from ..models.vulnerability import Vulnerability


def format_table(vulnerabilities: List[Vulnerability]) -> str:
    if not vulnerabilities:
        return "No vulnerabilities found."
    headers = ["Package", "Version", "CVE ID", "Severity", "Description"]
    rows = []
    for v in vulnerabilities:
        rows.append([
            v.package or "N/A",
            v.affected_version or "N/A",
            v.cve_id,
            v.severity,
            v.description[:60] + "..." if len(v.description) > 60 else v.description,
        ])
    return tabulate(rows, headers=headers, tablefmt="grid")


def format_json(vulnerabilities: List[Vulnerability]) -> str:
    return json.dumps([v.to_dict() for v in vulnerabilities], indent=2)


def format_csv(vulnerabilities: List[Vulnerability]) -> str:
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Package", "Version", "CVE ID", "Severity", "CVSS Score", "Description"])
    for v in vulnerabilities:
        writer.writerow([
            v.package or "",
            v.affected_version or "",
            v.cve_id,
            v.severity,
            v.cvss_score or "",
            v.description,
        ])
    return output.getvalue()