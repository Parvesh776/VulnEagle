from jinja2 import Environment, FileSystemLoader
import os
from datetime import datetime

def generate_html_report(data, output_file="vulneagle_report.html"):
    env = Environment(loader=FileSystemLoader(os.path.dirname(__file__)))

    template_str = """
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <title>VulnEagle Scan Report</title>
        <style>
            body { font-family: Arial, sans-serif; padding: 30px; background: #f4f4f4; }
            h1 { color: #333; }
            table { width: 100%; border-collapse: collapse; margin-top: 20px; }
            th, td { padding: 12px 16px; border: 1px solid #ccc; }
            th { background-color: #222; color: #fff; }
            tr:nth-child(even) { background-color: #e9e9e9; }
            .vuln-xss { color: orange; font-weight: bold; }
            .vuln-sqli { color: red; font-weight: bold; }
        </style>
    </head>
    <body>
        <h1>VulnEagle Scan Report</h1>
        <p><strong>Generated:</strong> {{ timestamp }}</p>
        <table>
            <tr><th>Endpoint</th><th>Vulnerability</th><th>Payload</th></tr>
            {% for item in results %}
            <tr>
                <td>{{ item.url }}</td>
                <td class="vuln-{{ item.type | lower }}">{{ item.type }}</td>
                <td>{{ item.payload }}</td>
            </tr>
            {% endfor %}
        </table>
    </body>
    </html>
    """
    template = env.from_string(template_str)
    output = template.render(results=data, timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    with open(output_file, "w", encoding="utf-8") as f:
        f.write(output)

    print(f"[+] HTML report saved as: {output_file}")


if __name__ == "__main__":
    sample_results = [
        {"url": "https://test.com/search?q=<script>", "type": "XSS", "payload": "<script>alert(1)</script>"},
        {"url": "https://test.com/login?id=1' OR 1=1 --", "type": "SQLi", "payload": "' OR 1=1 --"}
    ]

    generate_html_report(sample_results)