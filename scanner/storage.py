import sqlite3
import json
from datetime import datetime
from pathlib import Path
from typing import Any, Optional


class Storage:
    def __init__(self, db: str = "scanner.db"):
        # Ensure parent folder exists (e.g., data/scanner.db)
        db_path = Path(db)
        if db_path.parent and str(db_path.parent) not in ("", "."):
            db_path.parent.mkdir(parents=True, exist_ok=True)

        # SQLite connection
        self.conn = sqlite3.connect(
            str(db_path),
            timeout=10,               # busy timeout for concurrent reads/writes
            check_same_thread=False,  # safer if accessed across threads
        )
        self.conn.row_factory = sqlite3.Row

        # Pragmas (safe defaults for web apps)
        self.conn.execute("PRAGMA journal_mode=WAL;")
        self.conn.execute("PRAGMA synchronous=NORMAL;")
        self.conn.execute("PRAGMA foreign_keys=ON;")
        self.conn.execute("PRAGMA busy_timeout=5000;")

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
    def save_scan(self, target: str, score_data: dict, findings: list[dict], raw_json: Optional[dict] = None) -> int:
        cursor = self.conn.cursor()

        cursor.execute(
            """
            INSERT INTO scans (target, score, grade, timestamp, raw_json)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                target,
                int(score_data.get("score", 0) or 0),
                str(score_data.get("grade", "N/A")),
                datetime.utcnow().isoformat(),
                json.dumps(raw_json) if raw_json else None,
            )
        )

        scan_id = cursor.lastrowid

        for f in findings or []:
            cursor.execute(
                """
                INSERT INTO findings (scan_id, title, severity, description, metadata)
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
        return int(scan_id)

    # -------------------------
    # Get Latest Scan
    # -------------------------
    def get_latest_scan(self, target: str) -> Optional[dict]:
        cursor = self.conn.cursor()

        row = cursor.execute("""
            SELECT * FROM scans
            WHERE target = ?
            ORDER BY id DESC
            LIMIT 1
        """, (target,)).fetchone()

        if not row:
            return None

        raw = row["raw_json"]
        if raw:
            try:
                return json.loads(raw)
            except Exception:
                pass

        return {
            "target": row["target"],
            "score": row["score"],
            "grade": row["grade"],
            "timestamp": row["timestamp"],
        }

    # -------------------------
    # Get Findings for Scan
    # -------------------------
    def get_findings(self, scan_id: int) -> list[dict]:
        cursor = self.conn.cursor()

        rows = cursor.execute("""
            SELECT * FROM findings
            WHERE scan_id = ?
        """, (scan_id,)).fetchall()

        out = []
        for r in rows:
            out.append({
                "title": r["title"],
                "severity": r["severity"],
                "description": r["description"],
                "metadata": json.loads(r["metadata"]) if r["metadata"] else {},
            })
        return out

    # -------------------------
    # Close
    # -------------------------
    def close(self):
        try:
            self.conn.close()
        except Exception:
            pass