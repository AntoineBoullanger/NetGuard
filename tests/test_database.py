import sqlite3

from app.storage import database


def test_initialize_database_creates_alerts_table(tmp_path, monkeypatch):
    database_path = tmp_path / "test_netguard.db"

    monkeypatch.setattr(
        database,
        "DATABASE_PATH",
        database_path,
    )

    database.initialize_database()

    with sqlite3.connect(database_path) as connection:
        result = connection.execute("""
            SELECT name
            FROM sqlite_master
            WHERE type = 'table'
              AND name = 'alerts'
        """).fetchone()

    assert result is not None


def test_save_and_retrieve_alert(tmp_path, monkeypatch):
    database_path = tmp_path / "test_netguard.db"

    monkeypatch.setattr(
        database,
        "DATABASE_PATH",
        database_path,
    )

    database.initialize_database()

    alert = {
        "timestamp": "2026-10-14 12:00:00",
        "severity": "WARNING",
        "rule": "Sensitive remote port",
        "message": "Connection to port 3389.",
        "connection": {
            "remote_address": "192.168.1.20:3389",
            "pid": 1234,
        },
    }

    alert_id = database.save_alert(alert)
    saved_alerts = database.get_recent_alerts()

    assert alert_id is not None
    assert len(saved_alerts) == 1
    assert saved_alerts[0]["severity"] == "WARNING"
    assert saved_alerts[0]["rule"] == "Sensitive remote port"
    assert saved_alerts[0]["remote_address"] == "192.168.1.20:3389"
    assert saved_alerts[0]["pid"] == 1234


def test_get_recent_alerts_respects_limit(tmp_path, monkeypatch):
    database_path = tmp_path / "test_netguard.db"

    monkeypatch.setattr(
        database,
        "DATABASE_PATH",
        database_path,
    )

    database.initialize_database()

    for index in range(3):
        database.save_alert({
            "timestamp": f"2026-10-14 12:00:0{index}",
            "severity": "INFO",
            "rule": "Test rule",
            "message": f"Test alert {index}",
            "connection": {},
        })

    alerts = database.get_recent_alerts(limit=2)

    assert len(alerts) == 2
    assert alerts[0]["message"] == "Test alert 2"