#feed_loader.py
import os
import csv
import json
import requests
from modules.config import DOWNLOADED_DIR

class FeedLoader:

    def __init__(self):
        self.supported_formats = [".txt", ".csv", ".json",".stix"]

    def load_txt(self, filepath):
        with open(filepath, "r", encoding="utf-8") as file:
            return file.read()

    def load_csv(self, filepath):
        data = []
        with open(
            filepath,
            "r",
            encoding="utf-8"
        ) as file:
            sample = file.read(1024)
            file.seek(0)
            delimiter = ","
            if "\t" in sample:
                delimiter = "\t"
            reader = csv.DictReader(
                file,
                delimiter=delimiter
            )
            for row in reader:
                data.append(row)
        return data

    def load_json(self, filepath):
        with open(filepath, "r", encoding="utf-8") as file:
            return json.load(file)

    def load_stix(self, filepath):
        with open(
            filepath,
            "r",
            encoding="utf-8"
        ) as file:
            return json.load(file)
    
    def load_url(self, url):
        print(f"Connecting to: {url}")
        response = requests.get(url, timeout=10)
        print(
            f"Downloaded: {len(response.text)} bytes"
        )
        response.raise_for_status()
        content = response.text
        filename = (
            url.split("/")[-1]
            or "feed.txt"
        )
        save_path = DOWNLOADED_DIR / filename
        os.makedirs(
            "feeds/downloaded",
            exist_ok=True
        )
        with open(
            save_path,
            "w",
            encoding="utf-8"
        ) as file:
            file.write(content)
        print(
            f"Saved URL feed: {save_path}"
        )
        return content

    def load_feed_urls(
        self,
        filepath
    ):
        urls = []
        with open(
            filepath,
            "r",
            encoding="utf-8"
        ) as file:
            for line in file:
                line = line.strip()
                if line:
                    urls.append(line)
        return urls

    def load_feed(self, filepath):
        extension = os.path.splitext(filepath)[1].lower()
        if extension == ".txt":
            content = self.load_txt(filepath)
        elif extension == ".csv":
            content = self.load_csv(filepath)
        elif extension == ".json":
            content = self.load_json(filepath)
        elif extension == ".stix":
            content = self.load_stix(filepath)
        else:
            raise ValueError(
                f"Unsupported feed format: {extension}"
            )
        return {
            "feed_name": os.path.basename(filepath),
            "feed_type": extension,
            "content": content
        }
    
    def is_url_feed_file(
        self,
        filepath
    ):
        with open(
            filepath,
            "r",
            encoding="utf-8"
        ) as file:
            lines = [
                line.strip()
                for line in file
                if line.strip()
            ]
        if not lines:
            return False
        for line in lines:
            if not (
                line.startswith("http://")
                or
                line.startswith("https://")
            ):
                return False
        return True
    
    