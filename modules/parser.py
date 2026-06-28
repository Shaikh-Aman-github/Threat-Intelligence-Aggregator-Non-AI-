#parser.py
import re

class IOCParser:

    IOC_PATTERNS = {
        "ip":
        r"\b(?:\d{1,3}\.){3}\d{1,3}\b",

        "url":
        r"https?://[^\s]+",

        "email":
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",

        "md5":
        r"\b[a-fA-F0-9]{32}\b",

        "sha256":
        r"\b[a-fA-F0-9]{64}\b",

        "domain":
        r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b"
    }

    def parse_text(self, text):
        extracted_iocs = []
        for ioc_type, pattern in self.IOC_PATTERNS.items():
            matches = re.findall(pattern, text)
            for match in matches:
                extracted_iocs.append({
                    "indicator": match,
                    "type": ioc_type
                })
        return extracted_iocs
    
    