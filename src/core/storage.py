"""High-performance SQLite + FTS5 forensic storage backend."""

import json
import sqlite3
from typing import Any, Dict, List, Optional


class ForensicStorage:
    """Manages persistent storage, indexing, and FTS5 search for normalized EVTX events."""

    def __init__(self, db_path: str):
        self.db_path = db_path
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row
        self._configure_pragmas()
        self._init_schema()

    def _configure_pragmas(self) -> None:
        """Optimizes SQLite for high-speed bulk forensic ingestion."""
        cursor = self.conn.cursor()
        cursor.execute("PRAGMA journal_mode = WAL;")
        cursor.execute("PRAGMA synchronous = NORMAL;")
        cursor.execute("PRAGMA temp_store = MEMORY;")
        cursor.execute("PRAGMA cache_size = -64000;")
        self.conn.commit()

    def _init_schema(self) -> None:
        """Creates the core events table, indexes, external-content FTS5 table, and alerts table."""
        cursor = self.conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                computer TEXT,
                channel TEXT,
                provider TEXT,
                source_file TEXT,
                event_id INTEGER,
                record_id INTEGER,
                category TEXT,
                summary TEXT,
                user TEXT,
                target_user TEXT,
                logon_id TEXT,
                logon_guid TEXT,
                source_ip TEXT,
                destination_ip TEXT,
                process_name TEXT,
                parent_process TEXT,
                command_line TEXT,
                process_guid TEXT,
                parent_process_guid TEXT,
                raw_data_json TEXT
            );
        """)

        cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_event_id ON events(event_id);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_logon_id ON events(logon_id);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_process_guid ON events(process_guid);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_source_ip ON events(source_ip);")

        cursor.execute("""
            CREATE VIRTUAL TABLE IF NOT EXISTS events_fts USING fts5(
                summary,
                command_line,
                process_name,
                user,
                target_user,
                raw_data_json,
                content='events',
                content_rowid='id',
                tokenize='unicode61'
            );
        """)

        cursor.execute("""
            CREATE TRIGGER IF NOT EXISTS events_ai AFTER INSERT ON events BEGIN
                INSERT INTO events_fts(
                    rowid, summary, command_line, process_name, user, target_user, raw_data_json
                ) VALUES (
                    new.id, new.summary, new.command_line, new.process_name, new.user, new.target_user, new.raw_data_json
                );
            END;
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                rule_id TEXT,
                rule_title TEXT,
                severity TEXT,
                mitre_tags TEXT,
                computer TEXT,
                event_id INTEGER,
                summary TEXT
            );
        """)

        self.conn.commit()

    def insert_batch(self, events: List[Dict[str, Any]]) -> None:
        """Inserts a batch of normalized events in a single transaction."""
        if not events:
            return

        rows = [
            (
                ev.get("timestamp"),
                ev.get("computer"),
                ev.get("channel"),
                ev.get("provider"),
                ev.get("source_file"),
                ev.get("event_id"),
                ev.get("record_id"),
                ev.get("category"),
                ev.get("summary"),
                ev.get("user"),
                ev.get("target_user"),
                ev.get("logon_id"),
                ev.get("logon_guid"),
                ev.get("source_ip"),
                ev.get("destination_ip"),
                ev.get("process_name"),
                ev.get("parent_process"),
                ev.get("command_line"),
                ev.get("process_guid"),
                ev.get("parent_process_guid"),
                json.dumps(ev.get("raw_data", {}), default=str),
            )
            for ev in events
        ]

        cursor = self.conn.cursor()
        cursor.executemany("""
            INSERT INTO events (
                timestamp, computer, channel, provider, source_file, event_id, record_id,
                category, summary, user, target_user, logon_id, logon_guid, source_ip,
                destination_ip, process_name, parent_process, command_line, process_guid,
                parent_process_guid, raw_data_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        """, rows)
        self.conn.commit()

    def insert_alerts(self, alerts: List[Dict[str, Any]]) -> None:
        """Persists Sigma detection rule alerts into the SQLite alerts table."""
        if not alerts:
            return

        rows = [
            (
                al.get("timestamp"),
                al.get("rule_id"),
                al.get("rule_title"),
                al.get("severity"),
                json.dumps(al.get("mitre_tags", [])),
                al.get("computer"),
                al.get("event_id"),
                al.get("summary"),
            )
            for al in alerts
        ]

        cursor = self.conn.cursor()
        cursor.executemany("""
            INSERT INTO alerts (
                timestamp, rule_id, rule_title, severity, mitre_tags, computer, event_id, summary
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?);
        """, rows)
        self.conn.commit()

    def search_fts(self, fts_query: str, limit: int = 1000) -> List[Dict[str, Any]]:
        """Executes a full-text FTS5 MATCH query ordered chronologically."""
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT e.*
            FROM events e
            JOIN events_fts fts ON e.id = fts.rowid
            WHERE events_fts MATCH ?
            ORDER BY e.timestamp ASC
            LIMIT ?;
        """, (fts_query, limit))
        return [dict(row) for row in cursor.fetchall()]

    def query_events(
        self,
        event_ids: Optional[List[int]] = None,
        keyword: Optional[str] = None,
        logon_id: Optional[str] = None,
        source_ip: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Structured SQL filtering across indexed forensic columns."""
        if keyword:
            return self.search_fts(keyword)

        clauses = []
        params: List[Any] = []

        if event_ids:
            placeholders = ",".join("?" for _ in event_ids)
            clauses.append(f"event_id IN ({placeholders})")
            params.extend(event_ids)
        if logon_id:
            clauses.append("logon_id = ?")
            params.append(logon_id)
        if source_ip:
            clauses.append("source_ip = ?")
            params.append(source_ip)

        where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        cursor = self.conn.cursor()
        cursor.execute(f"SELECT * FROM events {where_sql} ORDER BY timestamp ASC;", params)
        return [dict(row) for row in cursor.fetchall()]

    def get_all_alerts(self) -> List[Dict[str, Any]]:
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM alerts ORDER BY timestamp ASC;")
        return [dict(row) for row in cursor.fetchall()]

    def close(self) -> None:
        self.conn.close()
