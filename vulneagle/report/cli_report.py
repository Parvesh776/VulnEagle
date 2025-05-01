from rich.console import Console
from rich.table import Table

console = Console()

def generate_cli_report(results):
    table = Table(title="VulnEagle CLI Report")

    table.add_column("Endpoint", style="cyan", overflow="fold")
    table.add_column("Vuln Type", style="magenta")
    table.add_column("Payload", style="green")

    for entry in results:
        table.add_row(entry['url'], entry['type'], entry['payload'])

    console.print(table)

if __name__ == "__main__":
    sample_results = [
        {"url": "https://test.com/search?q=<script>", "type": "XSS", "payload": "<script>alert(1)</script>"},
        {"url": "https://test.com/login?id=1' OR 1=1 --", "type": "SQLi", "payload": "' OR 1=1 --"}
    ]

    from cli_report import generate_cli_report
    from html_report import generate_html_report

    generate_cli_report(sample_results)
    generate_html_report(sample_results)