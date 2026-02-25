import sqlite3
import json
from datetime import datetime


class Storage:
    def __init__(self, db="scanner.db"):
        self.conn = sqlite3.connect(db)
        self.conn.row_factory = sqlite3.Row
        self._create_tables()

    # -------------------------
    # DB Schema
    # -------------------------
    def _create_tables(self):
        self.conn.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT,
            score INTEGER,
            grade TEXT,
            timestamp TEXT,
            raw_json TEXT
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

        self.conn.commit()

    # -------------------------
    # Save Scan
    # -------------------------
    def save_scan(self, target, score_data, findings, raw_json=None):
        """
        Saves scan summary + findings.
        Compatible with old and new engine versions.
        """
        cursor = self.conn.cursor()

        cursor.execute(
            """
            INSERT INTO scans
            (target, score, grade, timestamp, raw_json)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                target,
                score_data.get("score", 0),
                score_data.get("grade", "N/A"),
                datetime.utcnow().isoformat(),
                json.dumps(raw_json) if raw_json else None,
            )
        )

        scan_id = cursor.lastrowid

        for f in findings:
            cursor.execute(
                """
                INSERT INTO findings
                (scan_id, title, severity, description, metadata)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    scan_id,
                    f.get("title", ""),
                    f.get("severity", "Info"),
                    f.get("description", ""),
                    json.dumps(f.get("metadata", {})),
                )
            )

        self.conn.commit()
        return scan_id

    # -------------------------
    # Get Latest Scan (Elite Engine Support)
    # -------------------------
    def get_latest_scan(self, target):
        cursor = self.conn.cursor()

        row = cursor.execute("""
            SELECT * FROM scans
            WHERE target = ?
            ORDER BY id DESC
            LIMIT 1
        """, (target,)).fetchone()

        if not row:
            return None

        if row["raw_json"]:
            try:
                return json.loads(row["raw_json"])
            except Exception:
                pass

        return {
            "target": row["target"],
            "score": row["score"],
            "grade": row["grade"],
            "timestamp": row["timestamp"]
        }

    # -------------------------
    # Get Findings for Scan
    # -------------------------
    def get_findings(self, scan_id):
        cursor = self.conn.cursor()

        rows = cursor.execute("""
            SELECT * FROM findings
            WHERE scan_id = ?
        """, (scan_id,)).fetchall()

        findings = []
        for r in rows:
            findings.append({
                "title": r["title"],
                "severity": r["severity"],
                "description": r["description"],
                "metadata": json.loads(r["metadata"]) if r["metadata"] else {}
            })

        return findings

    # -------------------------
    # Close DB
    # -------------------------
    def close(self):
        self.conn.close()