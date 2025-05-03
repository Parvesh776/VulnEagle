import json
import datetime

def save_json(report_data, filename="report.json"):
    with open(filename, "w") as f:
        json.dump(report_data, f, indent=4)
    print(f"[+] JSON report saved as {filename}")


def save_text(report_data, filename="report.txt"):
    with open(filename, "w") as f:
        f.write("=== VulnEagle Scan Report ===\n")
        f.write(f"Scan Start : {report_data['timestamp']['start']}\n")
        f.write(f"Scan End   : {report_data['timestamp']['end']}\n")
        f.write(f"Duration   : {report_data['timestamp']['duration']}\n\n")

        f.write("---- Discovered Forms ----\n")
        for form in report_data["forms"]:
            f.write(json.dumps(form, indent=2) + "\n")

        f.write("\n---- Headers ----\n")
        f.write(json.dumps(report_data["headers"], indent=2) + "\n")

        f.write("\n---- Cookies ----\n")
        f.write(json.dumps(report_data["cookies"], indent=2) + "\n")

        f.write("\n---- Tokens ----\n")
        f.write(json.dumps(report_data["tokens"], indent=2) + "\n")

        f.write("\n---- Misconfigurations ----\n")
        for issue in report_data["misconfig"]:
            f.write(f"- {issue}\n")
    print(f"[+] Text report saved as {filename}")


def save_html(report_data, filename="report.html"):
    html = f"""<!DOCTYPE html>
<html>
<head>
    <title>VulnEagle Scan Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1, h2 {{ color: #333; }}
        pre {{ background: #f4f4f4; padding: 10px; overflow-x: auto; }}
    </style>
</head>
<body>
    <h1>🦅 VulnEagle Scan Report</h1>
    <p><strong>Start:</strong> {report_data['timestamp']['start']}</p>
    <p><strong>End:</strong> {report_data['timestamp']['end']}</p>
    <p><strong>Duration:</strong> {report_data['timestamp']['duration']}</p>

    <h2>Discovered Forms</h2>
    <pre>{json.dumps(report_data["forms"], indent=2)}</pre>

    <h2>Headers</h2>
    <pre>{json.dumps(report_data["headers"], indent=2)}</pre>

    <h2>Cookies</h2>
    <pre>{json.dumps(report_data["cookies"], indent=2)}</pre>

    <h2>Tokens</h2>
    <pre>{json.dumps(report_data["tokens"], indent=2)}</pre>

    <h2>Misconfigurations</h2>
    <ul>
        {''.join(f"<li>{m}</li>" for m in report_data['misconfig'])}
    </ul>
</body>
</html>"""

    with open(filename, "w") as f:
        f.write(html)
    print(f"[+] HTML report saved as {filename}")


def generate_report(report_data, format="html"):
    if format == "html":
        save_html(report_data)
    elif format == "json":
        save_json(report_data)
    elif format == "txt":
        save_text(report_data)
    else:
        print(f"[!] Unknown format: {format}")
