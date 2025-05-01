
# Expose all core modules
from .recon import js_scraper
from .scanner import fuzz_engine, vuln_mapper
from .report import html_report
from .auth import session_handler

__version__ = "1.0.0"
__all__ = [
    "js_scraper",
    "fuzz_engine",
    "vuln_mapper",
    "html_report",
    "session_handler"
]
