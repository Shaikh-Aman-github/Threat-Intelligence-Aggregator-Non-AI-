#blocklist_generator.py
import json
import csv

class BlocklistGenerator:

    def generate_ip_blocklist(
        self,
        normalized_iocs,
        output_file="output/ip_blocklist.txt"
    ):
        ips = set()
        for ioc in normalized_iocs:
            if ioc["type"] == "IP":
                ips.add(
                    ioc["indicator"]
                )
        with open(
            output_file,
            "w",
            encoding="utf-8"
        ) as file:
            for ip in sorted(ips):
                file.write(f"{ip}\n")
        print(
            f"IP Blocklist saved: {output_file}"
        )

    def generate_domain_blocklist(
        self,
        normalized_iocs,
        output_file="output/domain_blocklist.txt"
    ):
        domains = set()
        for ioc in normalized_iocs:
            if ioc["type"] == "DOMAIN":
                domains.add(
                    ioc["indicator"]
                )
        with open(
            output_file,
            "w",
            encoding="utf-8"
        ) as file:
            for domain in sorted(domains):
                file.write(f"{domain}\n")
        print(
            f"Domain Blocklist saved: "
            f"{output_file}"
        )
    
    def generate_url_blocklist(
        self,
        normalized_iocs,
        output_file="output/url_blocklist.txt"
    ):
        urls = set()
        for ioc in normalized_iocs:
            if ioc["type"] == "URL":
                urls.add(
                    ioc["indicator"]
                )
        with open(
            output_file,
            "w",
            encoding="utf-8"
        ) as file:
            for url in sorted(urls):
                file.write(f"{url}\n")
        print(
            f"URL Blocklist saved: "
            f"{output_file}"
        )
    
    def generate_hash_blocklist(
        self,
        normalized_iocs,
        output_file="output/hash_blocklist.txt"
    ):
        hashes = set()
        for ioc in normalized_iocs:
            if ioc["type"] in [
                "MD5",
                "SHA256"
            ]:
                hashes.add(
                    ioc["indicator"]
                )
        with open(
            output_file,
            "w",
            encoding="utf-8"
        ) as file:
            for hash_value in sorted(hashes):
                file.write(
                    f"{hash_value}\n"
                )
        print(
            f"Hash Blocklist saved: "
            f"{output_file}"
        )

    def generate_email_blocklist(
        self,
        normalized_iocs,
        output_file="output/email_blocklist.txt"
    ):
        emails = set()
        for ioc in normalized_iocs:
            if ioc["type"] == "EMAIL":
                emails.add(
                    ioc["indicator"]
                )
        with open(
            output_file,
            "w",
            encoding="utf-8"
        ) as file:
            for email in sorted(emails):
                file.write(
                    f"{email}\n"
                )
        print(
            f"Email Blocklist saved: "
            f"{output_file}"
        )

    def export_blocklists_json(
        self,
        normalized_iocs,
        output_file="output/blocklists.json"
    ):
        blocklists = {
            "ips": [],
            "domains": [],
            "urls": [],
            "hashes": [],
            "emails": []
        }
        for ioc in normalized_iocs:
            ioc_type = ioc["type"]
            indicator = ioc["indicator"]
            if ioc_type == "IP":
                blocklists["ips"].append(
                    indicator
                )
            elif ioc_type == "DOMAIN":
                blocklists["domains"].append(
                    indicator
                )
            elif ioc_type == "URL":
                blocklists["urls"].append(
                    indicator
                )
            elif ioc_type in [
                "MD5",
                "SHA256"
            ]:
                blocklists["hashes"].append(
                    indicator
                )
            elif ioc_type == "EMAIL":
                blocklists["emails"].append(
                    indicator
                )
        with open(
            output_file,
            "w",
            encoding="utf-8"
        ) as file:
            json.dump(
                blocklists,
                file,
                indent=4
            )
        print(
            f"JSON Blocklist saved: "
            f"{output_file}"
        )

    def export_blocklists_csv(
        self,
        normalized_iocs,
        output_file="output/blocklists.csv"
    ):
        with open(
            output_file,
            "w",
            newline="",
            encoding="utf-8"
        ) as file:
            writer = csv.writer(
                file
            )
            writer.writerow([
                "indicator",
                "type"
            ])
            for ioc in normalized_iocs:
                writer.writerow([
                    ioc["indicator"],
                    ioc["type"]
                ])
        print(
            f"CSV Blocklist saved: "
            f"{output_file}"
        )