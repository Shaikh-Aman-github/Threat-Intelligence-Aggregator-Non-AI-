#database.py
import sqlite3
from modules.config import DATABASE_FILE

class ThreatDatabase:
    def __init__(
        self,
        db_path=str(DATABASE_FILE)
    ):
        self.connection = sqlite3.connect(
            db_path
        )
        self.create_table()

    def create_table(self):
        cursor = self.connection.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS iocs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                indicator TEXT,
                type TEXT,
                source TEXT,
                category TEXT,
                severity TEXT,
                timestamp TEXT
            )
            """
        )
        self.connection.commit()

    def insert_ioc(
        self,
        ioc
    ):
        cursor = self.connection.cursor()
        cursor.execute(
            """
            INSERT INTO iocs (
                indicator,
                type,
                source,
                category,
                severity,
                timestamp
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                ioc["indicator"],
                ioc["type"],
                ioc["source"],
                ioc["category"],
                ioc["severity"],
                ioc["timestamp"]
            )
        )
        self.connection.commit()

    def insert_many(
        self,
        iocs
    ):
        cursor = self.connection.cursor()
        cursor.executemany(
            """
            INSERT INTO iocs (
                indicator,
                type,
                source,
                category,
                severity,
                timestamp
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    ioc["indicator"],
                    ioc["type"],
                    ioc["source"],
                    ioc["category"],
                    ioc["severity"],
                    ioc["timestamp"]
                )
                for ioc in iocs
            ]
        )
        self.connection.commit()

    def get_all_iocs(self):
        cursor = self.connection.cursor()
        cursor.execute(
            "SELECT * FROM iocs"
        )
        return cursor.fetchall()

    def get_count(self):
        cursor = self.connection.cursor()
        cursor.execute(
            "SELECT COUNT(*) FROM iocs"
        )
        return cursor.fetchone()[0]

    def clear_table(self):
        cursor = self.connection.cursor()
        cursor.execute(
            "DELETE FROM iocs"
        )
        self.connection.commit()

    def close(self):
        self.connection.close()

    