import sqlite3
from pathlib import Path


DATABASE_PATH = (
    Path(__file__).resolve().parents[2]
    / "netguard.db"
)


def get_connection():
    """Ouvre une connexion à la base de données NetGuard."""
    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_database():
    """Crée les tables nécessaires si elles n'existent pas."""
    with get_connection() as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                severity TEXT NOT NULL,
                rule TEXT NOT NULL,
                message TEXT NOT NULL,
                remote_address TEXT,
                pid INTEGER
            )
        """)

        connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_alerts_timestamp
            ON alerts(timestamp)
        """)


def save_alert(alert):
    """Enregistre une alerte et renvoie son identifiant."""
    connection_data = alert.get("connection", {})

    with get_connection() as connection:
        cursor = connection.execute("""
            INSERT INTO alerts (
                timestamp,
                severity,
                rule,
                message,
                remote_address,
                pid
            )
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            alert.get("timestamp", ""),
            alert.get("severity", "INFO"),
            alert.get("rule", "Unknown"),
            alert.get("message", ""),
            connection_data.get("remote_address"),
            connection_data.get("pid"),
        ))

        return cursor.lastrowid


def get_recent_alerts(limit=100):
    """Récupère les alertes les plus récentes."""
    with get_connection() as connection:
        rows = connection.execute("""
            SELECT *
            FROM alerts
            ORDER BY id DESC
            LIMIT ?
        """, (limit,)).fetchall()

        return [dict(row) for row in rows]