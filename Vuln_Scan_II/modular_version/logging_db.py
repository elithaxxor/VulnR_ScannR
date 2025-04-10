# logging_db.py

import logging
import sqlite3
import sys
from datetime import datetime

class SQLiteHandler(logging.Handler):
    """
    A custom logging handler that writes log records to a SQLite 'logs' table.
    """
    def __init__(self, db_path="smb_enum.db"):
        super().__init__()
        self.db_path = db_path
        self._initialize_database()

    def _initialize_database(self):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('''
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                level TEXT,
                message TEXT
            )
        ''')
        conn.commit()
        conn.close()

    def emit(self, record):
        """
        Write log record into 'logs' table.
        """
        try:
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            ts = self.formatTime(record, "%Y-%m-%d %H:%M:%S")
            level = record.levelname
            message = self.format(record)
            c.execute(
                "INSERT INTO logs (timestamp, level, message) VALUES (?, ?, ?)",
                (ts, level, message)
            )
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"[DB LOG FAILURE] {e}", file=sys.stderr)

class DBLogger:
    """
    Encapsulates logger setup: console + SQLite.
    Returns a logger instance for the entire application.
    """
    def __init__(self, db_path="smb_enum.db"):
        self.db_path = db_path
        self.logger = logging.getLogger("SMBLogger")
        self.logger.setLevel(logging.INFO)
        self._setup_handlers()

    def _setup_handlers(self):
        # Console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_format = logging.Formatter("[%(levelname)s] %(message)s")
        console_handler.setFormatter(console_format)
        self.logger.addHandler(console_handler)

        # SQLite handler
        db_handler = SQLiteHandler(self.db_path)
        db_format = logging.Formatter("%(message)s")
        db_handler.setFormatter(db_format)
        self.logger.addHandler(db_handler)

    def get_logger(self):
        return self.logger