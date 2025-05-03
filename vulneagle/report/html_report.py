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

        {% if results %}
        <h2>Vulnerabilities Found</h2>
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
        {% endif %}

        {% if forms %}
        <h2>Form Input Mapping</h2>
        <table>
            <tr><th>Action</th><th>Method</th><th>Inputs</th></tr>
            {% for form in forms %}
            <tr>
                <td>{{ form.action }}</td>
                <td>{{ form.method }}</td>
                <td>{{ form.inputs | join(", ") }}</td>
            </tr>
            {% endfor %}
        </table>
        {% endif %}

        {% if headers %}
        <h2>Headers</h2>
        {% for url, header_dict in headers.items() %}
        <h3>{{ url }}</h3>
        <table>
            <tr><th>Header</th><th>Value</th></tr>
            {% for k, v in header_dict.items() %}
            <tr><td>{{ k }}</td><td>{{ v }}</td></tr>
            {% endfor %}
        </table>
        {% endfor %}
        {% endif %}

        {% if cookies %}
        <h2>Cookies</h2>
        {% for url, cookie_dict in cookies.items() %}
        <h3>{{ url }}</h3>
        <table>
            <tr><th>Name</th><th>Value</th></tr>
            {% for k, v in cookie_dict.items() %}
            <tr><td>{{ k }}</td><td>{{ v }}</td></tr>
            {% endfor %}
        </table>
        {% endfor %}
        {% endif %}

        {% if tokens %}
        <h2>Auth Tokens</h2>
        {% for url, token_list in tokens.items() %}
        <h3>{{ url }}</h3>
        <ul>
            {% for token in token_list %}
            <li>{{ token }}</li>
            {% endfor %}
        </ul>
        {% endfor %}
        {% endif %}
    </body>
    </html>
    """

    template = env.from_string(template_str)
    output = template.render(
        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        results=data.get("results", []),
        forms=data.get("forms", []),
        headers=data.get("headers", {}),
        cookies=data.get("cookies", {}),
        tokens=data.get("tokens", {})
    )

    with open(output_file, "w", encoding="utf-8") as f:
        f.write(output)

    print(f"[+] HTML report saved as: {output_file}")


if __name__ == "__main__":
    sample_data = {
        "results": [
            {"url": "https://test.com/search?q=<script>", "type": "XSS", "payload": "<script>alert(1)</script>"},
            {"url": "https://test.com/login?id=1' OR 1=1 --", "type": "SQLi", "payload": "' OR 1=1 --"}
        ],
        "forms": [
            {"action": "/login", "method": "post", "inputs": ["username", "password"]}
        ],
        "headers": {
            "https://test.com": {"Authorization": "Bearer xyz123", "User-Agent": "Mozilla"}
        },
        "cookies": {
            "https://test.com": {"sessionid": "abc123"}
        },
        "tokens": {
            "https://test.com": ["Bearer xyz123", "auth_token=abc123"]
        }
    }

    generate_html_report(sample_data)
