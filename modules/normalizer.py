#normalizer.py
from datetime import datetime
import json

class IOCNormalizer:

    def normalize(self, iocs, source_name):

        normalized = []

        CATEGORY_MAP = {
            "IP": "Network IOC",
            "DOMAIN": "DNS IOC",
            "URL": "Web IOC",
            "EMAIL": "Email IOC",
            "MD5": "File IOC",
            "SHA256": "File IOC"
        }

        for ioc in iocs:
            normalized.append({
                "indicator": ioc["indicator"].strip().lower().rstrip("',\""),
                "type": ioc["type"].upper(),
                "source": source_name,
                "timestamp": datetime.now().strftime(
                    "%Y-%m-%d %H:%M:%S"
                ),
            
                "category": CATEGORY_MAP.get(
                    ioc["type"].upper(),
                    "Unknown"
                ),
                "severity": "Low"
            })
        return normalized
    
    def export_json(
        self,
        normalized_iocs,
        output_file="output/normalized_iocs.json"
    ):
        with open(
            output_file,
            "w",
            encoding="utf-8"
        ) as file:
            json.dump(
                normalized_iocs,
                file,
                indent=4
            )
        print(
            f"\nNormalized IOC database saved to: "
            f"{output_file}"
        )

        