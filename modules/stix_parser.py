import re


class STIXParser:

    def parse_stix(self, stix_data):
        extracted = []

        objects = stix_data.get(
            "objects",
            []
        )

        for obj in objects:
            if obj.get("type") != "indicator":
                continue
            pattern = obj.get(
                "pattern",
                ""
            )
            ip_match = re.search(
                r"ipv4-addr:value\s*=\s*'([^']+)'",
                pattern
            )
            if ip_match:
                extracted.append({
                    "indicator": ip_match.group(1),
                    "type": "ip"
                })
            domain_match = re.search(
                r"domain-name:value\s*=\s*'([^']+)'",
                pattern
            )
            if domain_match:
                extracted.append({
                    "indicator": domain_match.group(1),
                    "type": "domain"
                })
            url_match = re.search(
                r"url:value\s*=\s*'([^']+)'",
                pattern
            )

            if url_match:
                extracted.append({
                    "indicator": url_match.group(1),
                    "type": "url"
                })

            email_match = re.search(
                r"email-addr:value\s*=\s*'([^']+)'",
                pattern
            )

            if email_match:
                extracted.append({
                    "indicator": email_match.group(1),
                    "type": "email"
                })

        return extracted
    
    