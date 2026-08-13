import json, sqlite3, threading
from pathlib import Path
from .models import Detection

class AuditStore:
    def __init__(self, path: str = "/data/security.db") -> None:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.lock = threading.Lock()
        self.db.execute("""CREATE TABLE IF NOT EXISTS detections(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id TEXT UNIQUE,
            severity TEXT,
            action TEXT,
            anomaly_score REAL,
            payload TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )""")
        self.db.commit()

    def save(self, d: Detection) -> None:
        with self.lock:
            self.db.execute(
                "INSERT OR REPLACE INTO detections(event_id,severity,action,anomaly_score,payload) VALUES(?,?,?,?,?)",
                (d.event.event_id, d.severity, d.recommended_action, d.anomaly_score, d.model_dump_json())
            )
            self.db.commit()

    def latest(self, limit: int = 100) -> list[dict]:
        cur = self.db.execute("SELECT payload FROM detections ORDER BY id DESC LIMIT ?", (limit,))
        return [json.loads(r[0]) for r in cur.fetchall()]
