from app.detection.rules import detect_suspicious_connections


def test_detects_sensitive_remote_port():
    connections = [
        {
            "protocol": "TCP",
            "local_address": "192.168.1.10:50000",
            "remote_address": "192.168.1.20:3389",
            "status": "ESTABLISHED",
            "pid": 1234,
        }
    ]

    alerts = detect_suspicious_connections(connections)

    assert len(alerts) == 1
    assert alerts[0]["severity"] == "WARNING"
    assert alerts[0]["rule"] == "Sensitive remote port"


def test_ignores_connection_to_regular_port():
    connections = [
        {
            "protocol": "TCP",
            "local_address": "192.168.1.10:50000",
            "remote_address": "142.250.74.14:443",
            "status": "ESTABLISHED",
            "pid": 1234,
        }
    ]

    alerts = detect_suspicious_connections(connections)

    assert alerts == []


def test_detects_established_connection_without_pid():
    connections = [
        {
            "protocol": "TCP",
            "local_address": "192.168.1.10:50000",
            "remote_address": "142.250.74.14:443",
            "status": "ESTABLISHED",
            "pid": None,
        }
    ]

    alerts = detect_suspicious_connections(connections)

    assert len(alerts) == 1
    assert alerts[0]["rule"] == "Unknown process"


def test_handles_empty_connections():
    assert detect_suspicious_connections([]) == []