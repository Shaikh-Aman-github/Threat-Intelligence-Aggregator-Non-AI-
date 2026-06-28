#validator.py
import ipaddress
import re

class IOCValidator:

    def validate_ip(self, value):
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False

    def validate_domain(self, value):
        pattern = r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$"
        return bool(re.match(pattern, value))

    def validate_email(self, value):
        pattern = r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$"
        return bool(re.match(pattern, value))

    def validate_url(self, value):
        pattern = r"^https?://.+"
        return bool(re.match(pattern, value))

    def validate_md5(self, value):
        return bool(re.match(r"^[a-fA-F0-9]{32}$", value))

    def validate_sha256(self, value):
        return bool(re.match(r"^[a-fA-F0-9]{64}$", value))
    
    def is_valid(self, indicator, indicator_type):
        validators = {
            "ip": self.validate_ip,
            "domain": self.validate_domain,
            "email": self.validate_email,
            "url": self.validate_url,
            "md5": self.validate_md5,
            "sha256": self.validate_sha256
        }
        validator = validators.get(indicator_type)

        if validator:
            return validator(indicator)
        return False
    
    def clean_iocs(self, iocs):

        cleaned = []
        seen = set()

        for ioc in iocs:
            indicator = ioc["indicator"]
            indicator_type = ioc["type"]
            if not self.is_valid(indicator, indicator_type):
                continue
            key = (indicator, indicator_type)
            if key in seen:
                continue
            seen.add(key)
            cleaned.append(ioc)

        return cleaned
    
    