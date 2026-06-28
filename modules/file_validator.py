import os
import csv
import json
import requests

class FeedFileValidator:

    SUPPORTED_FORMATS = [
        ".txt",
        ".csv",
        ".json",
        ".stix"
    ]

    def validate_file(
        self,
        filepath
    ):
        if not os.path.exists(filepath):
            raise ValueError(
                f"File not found: {filepath}"
            )
        extension = os.path.splitext(
            filepath
        )[1].lower()

        if extension not in self.SUPPORTED_FORMATS:
            raise ValueError(
                f"Unsupported file format: {extension}"
            )

        if extension == ".txt":
            self.validate_txt(
                filepath
            )

        elif extension == ".csv":
            self.validate_csv(
                filepath
            )

        elif extension == ".json":
            self.validate_json(
                filepath
            )

        elif extension == ".stix":
            self.validate_stix(
                filepath
            )

        return True

    def validate_txt(
        self,
        filepath
    ):
        with open(
            filepath,
            "r",
            encoding="utf-8"
        ) as file:
            content = file.read().strip()
            if not content:
                raise ValueError(
                    f"Empty TXT file: {filepath}"
                )

    def validate_csv(
        self,
        filepath
    ):
        with open(
            filepath,
            "r",
            encoding="utf-8"
        ) as file:
            reader = csv.DictReader(
                file
            )
            headers = reader.fieldnames

            if not headers:
                raise ValueError(
                    f"Empty CSV file: {filepath}"
                )
            required_columns = [
                "indicator",
                "type"
            ]

            for column in required_columns:
                if column not in headers:
                    raise ValueError(
                        f"{filepath} missing required column: {column}"
                    )

    def validate_json(
        self,
        filepath
    ):
        try:
            with open(
                filepath,
                "r",
                encoding="utf-8"
            ) as file:
                data = json.load(
                    file
                )

            # Standard IOC JSON
            if isinstance(
                data,
                list
            ):
                return True

            # STIX Bundle
            if (
                isinstance(
                    data,
                    dict
                )
                and
                data.get("type") == "bundle"
                and
                "objects" in data
            ):
                return True

            raise ValueError(
                "JSON must contain either:\n"
                "- A list of IOC indicators\n"
                "OR\n"
                "- A valid STIX Bundle"
            )

        except json.JSONDecodeError:
            raise ValueError(
                f"Invalid JSON format: {filepath}"
            )

    def validate_stix(
        self,
        filepath
    ):
        try:
            with open(
                filepath,
                "r",
                encoding="utf-8"
            ) as file:
                data = json.load(
                    file
                )
            if "objects" not in data:
                raise ValueError(
                    f"Invalid STIX feed: {filepath}"
                )
        except json.JSONDecodeError:
            raise ValueError(
                f"Invalid STIX JSON: {filepath}"
            )
        
    def validate_url(
        self,
        url
    ):
        try:
            response = requests.head(
                url,
                allow_redirects=True,
                timeout=10
            )
            if response.status_code >= 400:
                raise ValueError(
                    f"URL unreachable: {url}"
                )
            return True

        except Exception as error:
            raise ValueError(
                f"Invalid URL: {url} ({error})"
            )
        
    def validate_feed_urls_file(
        self,
        filepath
    ):
        with open(
            filepath,
            "r",
            encoding="utf-8"
        ) as file:
            for line in file:
                url = line.strip()
                if not url:
                    continue
                self.validate_url(
                    url
                )
        return True
    
    

