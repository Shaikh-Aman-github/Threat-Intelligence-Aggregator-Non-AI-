#pipeline.py
import os
import shutil

from modules.feed_loader import FeedLoader
from modules.parser import IOCParser
from modules.validator import IOCValidator
from modules.normalizer import IOCNormalizer
from modules.correlator import IOCCorrelator
from modules.blocklist_generator import BlocklistGenerator
from modules.reporter import ThreatReporter
from modules.stix_parser import STIXParser
from modules.database import ThreatDatabase
from modules.file_validator import FeedFileValidator
from modules.config import FEEDS_DIR
from modules.config import UPLOADED_DIR

class ThreatIntelligencePipeline:

    def __init__(self):

        self.loader = FeedLoader()
        self.parser = IOCParser()
        self.validator = IOCValidator()
        self.normalizer = IOCNormalizer()
        self.correlator = IOCCorrelator()
        self.blocklist = BlocklistGenerator()
        self.reporter = ThreatReporter()
        self.stix_parser = STIXParser()
        self.database = ThreatDatabase()
        self.file_validator = FeedFileValidator()

    def process_feeds(self):

        logs = []

        all_normalized_iocs = []
        self.database.clear_table() # Clear old IOC records
        feeds_directory = str(FEEDS_DIR)
        
        if not os.path.exists(feeds_directory):
            print("Feeds directory not found.")
            return None

        files = [
            file
            for file in os.listdir(feeds_directory)
            if os.path.isfile(
                os.path.join(
                    feeds_directory,
                    file
                )
            )
        ]

        url_feed_file = os.path.join(
            feeds_directory,
            "feed_urls.txt"
        )

        if os.path.exists(
            url_feed_file
        ):
            urls = (
                self.loader.load_feed_urls(
                    url_feed_file
                )
            )
            for url in urls:
                try:
                    print(
                        f"Fetching URL Feed: {url}"
                    )
                    content = (
                        self.loader.load_url(
                            url
                        )
                    )
                    parsed = (
                        self.parser.parse_text(
                            content
                        )
                    )
                    cleaned = (
                        self.validator.clean_iocs(
                            parsed
                        )
                    )
                    normalized = (
                        self.normalizer.normalize(
                            cleaned,
                            url
                        )
                    )
                    for ioc in normalized:
                        self.database.insert_ioc(
                            ioc
                        )
                    all_normalized_iocs.extend(
                        normalized
                    )

                except Exception as error:
                    print(
                        f"URL Feed Error: "
                        f"{error}"
                    )

        if not files:
            print("No feeds found.")
            return None
        print("\nStarting Threat Intelligence Processing...\n")

        for file_name in files:
            if file_name == "feed_urls.txt":
                continue
            file_path = os.path.join(
                feeds_directory,
                file_name
            )
            message = f"Processing: {file_name}"
            print(message)
            logs.append(message)

            try:
                feed = self.loader.load_feed(
                    file_path
                )
                parsed = []

                if feed["feed_type"] == ".txt":
                    parsed = self.parser.parse_text(
                        feed["content"]
                    )
                elif feed["feed_type"] == ".csv":
                    for row in feed["content"]:
                        if (
                            "indicator" in row
                            and
                            "type" in row
                        ):
                            parsed.append({
                                "indicator": row["indicator"],
                                "type": row["type"]
                            })
                elif feed["feed_type"] == ".json":
                    if (
                        isinstance(feed["content"], dict)
                        and
                        "objects" in feed["content"]
                    ):
                        parsed = (
                            self.stix_parser.parse_stix(
                                feed["content"]
                            )
                        )
                    else:

                        for item in feed["content"]:
                            if (
                                "indicator" in item
                                and
                                "type" in item
                            ):
                                parsed.append({
                                    "indicator": item["indicator"],
                                    "type": item["type"]
                                })
                cleaned = self.validator.clean_iocs(
                    parsed
                )
                normalized = self.normalizer.normalize(
                    cleaned,
                    file_name
                )

                # Save into DB
                for ioc in normalized:
                    self.database.insert_ioc(
                        ioc
                    )
                all_normalized_iocs.extend(
                    normalized
                )

            except Exception as error:
                error_message = (
                    f"Error processing "
                    f"{file_name}: {error}"
                )
                print(error_message)
                logs.append(error_message)

            if not all_normalized_iocs:
                print("\nNo valid IOCs found.")
                return None

        self.normalizer.export_json(
            all_normalized_iocs
        )

        report = self.correlator.build_report(
            all_normalized_iocs
        )

        self.correlator.export_csv(
            report
        )

        self.blocklist.generate_ip_blocklist(
            all_normalized_iocs
        )

        self.blocklist.generate_domain_blocklist(
            all_normalized_iocs
        )

        self.blocklist.generate_url_blocklist(
            all_normalized_iocs
        )

        self.blocklist.generate_hash_blocklist(
            all_normalized_iocs
        )
        
        self.blocklist.generate_email_blocklist(
            all_normalized_iocs
        )

        self.blocklist.export_blocklists_json(
            all_normalized_iocs
        )

        self.blocklist.export_blocklists_csv(
            all_normalized_iocs
        )

        self.reporter.generate_pdf_report(
            all_normalized_iocs,
            report
        )

        print(
            "\nThreat Intelligence Processing Complete"
        )
        print(
            f"Database Records: "
            f"{self.database.get_count()}"
        )   
        urls = []

        url_feed_file = os.path.join(
            feeds_directory,
            "feed_urls.txt"
        )       
        stats = {
            "feeds_processed": len(files) + len(urls),
            "total_iocs": len(
                all_normalized_iocs
            ),
            "unique_iocs": len(
                set(
                    ioc["indicator"]
                    for ioc in all_normalized_iocs
                )
            ),
            "high_risk": len(
                [
                    item
                    for item in report
                    if item["severity"] == "High"
                ]
            ),
            "logs": logs
        }
        return stats
    
    def process_uploaded_feeds(
        self,
        file_paths
    ):
        logs = []
        all_normalized_iocs = []
        uploaded_directory = str(UPLOADED_DIR)

        os.makedirs(
            uploaded_directory,
            exist_ok=True
        )

        copied_files = []
        
        for file in os.listdir(uploaded_directory):
            full_path = os.path.join(
                uploaded_directory,
                file
            )
            if os.path.isfile(full_path):
                os.remove(full_path)

        for source_file in file_paths:
            self.file_validator.validate_file(
                source_file
            )
            destination = os.path.join(
                uploaded_directory,
                os.path.basename(source_file)
            )
            shutil.copy2(
                source_file,
                destination
            )
            copied_files.append(
                destination
            )
        print(
            f"\nCopied {len(copied_files)} feed(s) to "
            f"{uploaded_directory}"
        )

        self.database.clear_table()

        print(
            "\nProcessing Uploaded Feeds...\n"
        )

        for file_path in copied_files:
            try:
                self.file_validator.validate_file(
                    file_path
                )
                file_name = os.path.basename(
                    file_path
                )
                print(
                    f"Processing: {file_name}"
                )
                feed = self.loader.load_feed(
                    file_path
                )

                parsed = []

                if feed["feed_type"] == ".txt":
                    if self.loader.is_url_feed_file(file_path):
                        print(
                            "Detected URL Feed List"
                        )
                        urls = self.loader.load_feed_urls(
                            file_path
                        )

                        for url in urls:
                            try:
                                self.file_validator.validate_url(
                                    url
                                )
                                print(
                                    f"Fetching URL Feed: {url}"
                                )
                                content = self.loader.load_url(
                                    url
                                )
                                parsed = self.parser.parse_text(
                                    content
                                )
                                cleaned = self.validator.clean_iocs(
                                    parsed
                                )
                                normalized = self.normalizer.normalize(
                                    cleaned,
                                    url
                                )
                                self.database.insert_many(
                                    normalized
                                )
                                all_normalized_iocs.extend(
                                    normalized
                                )

                            except Exception as error:
                                print(
                                    f"URL Feed Error: {error}"
                                )
                        continue

                    else:
                        parsed = self.parser.parse_text(
                            feed["content"]
                        )

                elif feed["feed_type"] == ".csv":
                    for row in feed["content"]:
                        if (
                            "indicator" in row
                            and
                            "type" in row
                        ):
                            parsed.append({
                                "indicator": row["indicator"],
                                "type": row["type"]
                            })
                elif feed["feed_type"] == ".json":
                    if (
                        isinstance(
                            feed["content"],
                            dict
                        )
                        and
                        "objects" in feed["content"]
                    ):
                        parsed = (
                            self.stix_parser.parse_stix(
                                feed["content"]
                            )
                        )

                    else:
                        for item in feed["content"]:
                            if (
                                "indicator" in item
                                and
                                "type" in item
                            ):
                                parsed.append({
                                    "indicator": item["indicator"],
                                    "type": item["type"]
                                })

                cleaned = self.validator.clean_iocs(
                    parsed
                )

                normalized = self.normalizer.normalize(
                    cleaned,
                    file_name
                )

                self.database.insert_many(
                    normalized
                )

                all_normalized_iocs.extend(
                    normalized
                )

            except Exception as error:
                print(
                    f"Error processing "
                    f"{file_path}: {error}"
                )
                logs.append(
                    str(error)
                )

        if not all_normalized_iocs:
            print(
                "\nNo valid IOCs found."
            )
            return None

        report = self.correlator.build_report(
            all_normalized_iocs
        )

        self.normalizer.export_json(
            all_normalized_iocs
        )

        self.correlator.export_csv(
            report
        )

        self.blocklist.generate_ip_blocklist(
            all_normalized_iocs
        )

        self.blocklist.generate_domain_blocklist(
            all_normalized_iocs
        )

        self.blocklist.generate_url_blocklist(
            all_normalized_iocs
        )

        self.blocklist.generate_hash_blocklist(
            all_normalized_iocs
        )

        self.blocklist.generate_email_blocklist(
            all_normalized_iocs
        )

        self.blocklist.export_blocklists_json(
            all_normalized_iocs
        )

        self.blocklist.export_blocklists_csv(
            all_normalized_iocs
        )

        self.reporter.generate_pdf_report(
            all_normalized_iocs,
            report
        )

        print(
            "\nUploaded Feed Processing Complete"
        )

        return {
            "feeds_processed":
            len(file_paths),

            "total_iocs":
            len(all_normalized_iocs),

            "unique_iocs":
            len(
                set(
                    ioc["indicator"]
                    for ioc in all_normalized_iocs
                )
            ),
            "high_risk":
            len(
                [
                    item
                    for item in report
                    if item["severity"] == "High"
                ]
            ),

            "logs":
            logs
        }
    
    
    
