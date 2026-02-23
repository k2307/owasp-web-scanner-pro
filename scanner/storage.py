import sqlite3
import json
from datetime import datetime

class Storage:
    def __init__(self, db="scanner.db"):
        self.conn = sqlite3.connect(db)
        self._create_tables()

    def _create_tables(self):
        self.conn.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT,
            score INTEGER,
            grade TEXT,
            timestamp TEXT
        )
        """)
        self.conn.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            scan_id INTEGER,
            title TEXT,
            severity TEXT,
            description TEXT,
            metadata TEXT
        )
        """)

    def save_scan(self, target, score_data, findings):
        cursor = self.conn.cursor()
        cursor.execute(
            "INSERT INTO scans (target, score, grade, timestamp) VALUES (?, ?, ?, ?)",
            (target, score_data["score"], score_data["grade"], datetime.utcnow().isoformat())
        )
        scan_id = cursor.lastrowid

        for f in findings:
            cursor.execute(
                "INSERT INTO findings VALUES (?, ?, ?, ?, ?)",
                (
                    scan_id,
                    f["title"],
                    f["severity"],
                    f["description"],
                    json.dumps(f.get("metadata", {}))
                )
            )

        self.conn.commit()