"""Only sealed, redacted reports are persisted; reads return fresh objects."""
import sqlite3
import threading
from pathlib import Path
from app.models import InvestigationReport


class Database:
    def __init__(self, path: str):
        if path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(path, check_same_thread=False)
        self.lock = threading.RLock()
        with self.connection:
            self.connection.execute("CREATE TABLE IF NOT EXISTS reports (report_id TEXT PRIMARY KEY, payload TEXT NOT NULL)")

    def save(self, report: InvestigationReport):
        with self.lock, self.connection:
            self.connection.execute("INSERT INTO reports(report_id,payload) VALUES (?,?)", (report.bundle.report_id, report.model_dump_json(by_alias=True)))

    def get(self, report_id: str) -> InvestigationReport | None:
        with self.lock:
            row = self.connection.execute("SELECT payload FROM reports WHERE report_id=?", (report_id,)).fetchone()
        return InvestigationReport.model_validate_json(row[0]) if row else None

    def close(self):
        self.connection.close()
