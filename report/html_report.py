from datetime import datetime
import json

def generate_html_report(data):
    html = f"""
    <html>
    <head>
        <title>VulnEagle Report</title>
        <style>
            body {{
                font-family: Arial, sans-serif;
                background-color: #f4f4f4;
                padding: 20px;
                color: #333;
            }}
            h1, h2 {{
                color: #2c3e50;
            }}
            .section {{
                background-color: #fff;
                border-radius: 8px;
                padding: 20px;
                margin-bottom: 30px;
                box-shadow: 0 2px 5px rgba(0,0,0,0.1);
            }}
            pre {{
                background-color: #ecf0f1;
                padding: 10px;
                border-radius: 5px;
                overflow-x: auto;
            }}
            ul {{
                padding-left: 20px;
            }}
        </style>
    </head>
    <body>
        <h1>🛡️ VulnEagle Scan Report</h1>

        <div class="section">
            <h2>🕒 Scan Timestamps</h2>
            <p><strong>Start:</strong> {data['timestamp']['start']}</p>
            <p><strong>End:</strong> {data['timestamp']['end']}</p>
            <p><strong>Duration:</strong> {data['timestamp']['duration']}</p>
        </div>

        <div class="section">
            <h2>📝 Discovered Forms</h2>
            <pre>{format_json(data['forms'])}</pre>
        </div>

        <div class="section">
            <h2>🧠 Headers</h2>
            <pre>{format_json(data['headers'])}</pre>
        </div>

        <div class="section">
            <h2>🍪 Cookies</h2>
            <pre>{format_json(data['cookies'])}</pre>
        </div>

        <div class="section">
            <h2>🔐 Tokens</h2>
            <pre>{format_json(data['tokens'])}</pre>
        </div>

        <div class="section">
            <h2>⚠️ Misconfigurations</h2>
            <ul>
                {''.join(f"<li>{m}</li>" for m in data['misconfig'])}
            </ul>
        </div>

        <div class="section">
            <h2>🚨 Detected Vulnerabilities</h2>
            <ul>
                {''.join(f"<li>{escape(v)}</li>" for v in data.get('vulns', []))}
            </ul>
        </div>

    </body>
    </html>
    """

    with open("report.html", "w", encoding="utf-8") as f:
        f.write(html)
    print("[*] HTML report saved as report.html")


def format_json(obj):
    return json.dumps(obj, indent=2)


def escape(text):
    if isinstance(text, dict):
        text = json.dumps(text)
    return str(text).replace("<", "&lt;").replace(">", "&gt;")
