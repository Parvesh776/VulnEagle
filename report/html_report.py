from datetime import datetime
import json
from html import escape as html_escape

def generate_html_report(data, filename="report.html"):
    html = f"""
    <html>
    <head>
        <title>VulnEagle Report</title>
        <style>
            body {{
                font-family: Arial, sans-serif;
                background-color: #f9f9f9;
                padding: 20px;
                color: #333;
            }}
            h1, h2 {{
                color: #1a1a1a;
            }}
            .section {{
                background-color: #fff;
                border-radius: 10px;
                padding: 20px;
                margin-bottom: 30px;
                box-shadow: 0 2px 6px rgba(0,0,0,0.1);
            }}
            pre {{
                background-color: #f0f0f0;
                padding: 12px;
                border-radius: 5px;
                overflow-x: auto;
                white-space: pre-wrap;
                word-wrap: break-word;
            }}
            ul {{
                padding-left: 20px;
            }}
            li {{
                margin-bottom: 5px;
            }}
            .count {{
                font-size: 0.9em;
                color: #888;
            }}
        </style>
    </head>
    <body>
        <h1>🛡️ VulnEagle Scan Report</h1>

        <div class="section">
            <h2>🕒 Scan Timestamps</h2>
            <p><strong>Start:</strong> {html_escape(data.get('timestamp', {}).get('start', 'N/A'))}</p>
            <p><strong>End:</strong> {html_escape(data.get('timestamp', {}).get('end', 'N/A'))}</p>
            <p><strong>Duration:</strong> {html_escape(data.get('timestamp', {}).get('duration', 'N/A'))}</p>
        </div>

        <div class="section">
            <h2>📝 Discovered Forms <span class="count">({len(data.get('forms', []))})</span></h2>
            <pre>{format_json(data.get('forms', []))}</pre>
        </div>

        <div class="section">
            <h2>🧠 Headers</h2>
            <pre>{format_json(data.get('headers', []))}</pre>
        </div>

        <div class="section">
            <h2>🍪 Cookies</h2>
            <pre>{format_json(data.get('cookies', []))}</pre>
        </div>

        <div class="section">
            <h2>🔐 Tokens</h2>
            <pre>{format_json(data.get('tokens', []))}</pre>
        </div>

        <div class="section">
            <h2>⚠️ Misconfigurations <span class="count">({len(data.get('misconfig', []))})</span></h2>
            <ul>
                {''.join(f"<li>{html_escape(m)}</li>" for m in data.get('misconfig', []))}
            </ul>
        </div>

        <div class="section">
            <h2>🚨 Detected Vulnerabilities <span class="count">({len(data.get('vulns', []))})</span></h2>
            <ul>
                {''.join(f"<li>{html_escape(v)}</li>" for v in data.get('vulns', []))}
            </ul>
        </div>
    </body>
    </html>
    """

    with open(filename, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"[*] HTML report saved as {filename}")

def format_json(obj):
    try:
        return html_escape(json.dumps(obj, indent=2))
    except Exception:
        return html_escape(str(obj))
