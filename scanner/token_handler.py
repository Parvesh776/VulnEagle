import re
import json

class TokenExtractor:
    """
    Extracts potential tokens like JWTs, API keys, secrets from HTTP responses.
    """

    def __init__(self):
        # Regex patterns for various token types
        self.patterns = {
            "JWT": r"eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+",
            "Bearer": r"Bearer\s+([a-zA-Z0-9\-_\.=]+)",
            "API_KEY": r"api[_-]?key['\"]?\s*[:=]\s*['\"]([A-Za-z0-9\-_]{16,})['\"]",
            "Authorization": r"Authorization\s*[:=]\s*['\"]?(Bearer\s+[A-Za-z0-9\-_\.=]+)['\"]?",
            "Secret": r"(?i)(secret|token|key)['\"]?\s*[:=]\s*['\"]([A-Za-z0-9\-_]{16,})['\"]"
        }

    def extract_from_response(self, response):
        found_tokens = []

        # Combine headers and body for scanning
        combined = json.dumps(dict(response.headers)) + "\n" + response.text

        for name, pattern in self.patterns.items():
            matches = re.findall(pattern, combined)
            for match in matches:
                token = match if isinstance(match, str) else match[0]
                found_tokens.append({
                    "type": name,
                    "token": token
                })

        return found_tokens
