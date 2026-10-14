from datetime import datetime


def detect_suspicious_connections(
    connections: list[dict],
) -> list[dict]:
    """
    Analyse les connexions réseau et signale les situations
    qui méritent une vérification.
    """
    alerts = []

    for connection in connections:
        remote_address = connection.get("remote_address")
        status = connection.get("status")
        pid = connection.get("pid")

        # Règle 1 : connexion établie vers un port sensible
        if remote_address:
            try:
                remote_port = int(remote_address.rsplit(":", 1)[1])

                sensitive_ports = {
                    21: "FTP",
                    23: "Telnet",
                    445: "SMB",
                    3389: "RDP",
                }

                if remote_port in sensitive_ports:
                    alerts.append({
                        "timestamp": datetime.now().strftime(
                            "%Y-%m-%d %H:%M:%S"
                        ),
                        "severity": "WARNING",
                        "rule": "Sensitive remote port",
                        "message": (
                            f"Connexion vers le port {remote_port} "
                            f"({sensitive_ports[remote_port]})."
                        ),
                        "connection": connection,
                    })

            except (ValueError, IndexError):
                pass

        # Règle 2 : processus non identifié
        if status == "ESTABLISHED" and pid is None:
            alerts.append({
                "timestamp": datetime.now().strftime(
                    "%Y-%m-%d %H:%M:%S"
                ),
                "severity": "INFO",
                "rule": "Unknown process",
                "message": (
                    "Connexion établie sans identifiant de processus "
                    "disponible."
                ),
                "connection": connection,
            })

    return alerts