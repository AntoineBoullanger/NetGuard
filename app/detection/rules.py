from datetime import datetime
from collections import Counter


def detect_suspicious_connections(
    connections: list[dict],
) -> list[dict]:
    """
    Analyse les connexions réseau et signale les situations
    qui méritent une vérification.
    """
    alerts = []
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Règle 1 : ports distants sensibles
    sensitive_ports = {
        21: "FTP",
        23: "Telnet",
        445: "SMB",
        3389: "RDP",
    }

    # Compter les connexions vers chaque adresse distante
    remote_addresses = [
        connection.get("remote_address")
        for connection in connections
        if connection.get("remote_address")
    ]
    address_counts = Counter(remote_addresses)

    # Règle 2 : repérer les connexions répétées vers une même adresse
    repeated_addresses = {
        address
        for address, count in address_counts.items()
        if count >= 10
    }

    for connection in connections:
        remote_address = connection.get("remote_address")
        status = connection.get("status")
        pid = connection.get("pid")

        # Règle 1 : connexion vers un port sensible
        if remote_address:
            try:
                remote_port = int(remote_address.rsplit(":", 1)[1])

                if remote_port in sensitive_ports:
                    alerts.append({
                        "timestamp": timestamp,
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
                "timestamp": timestamp,
                "severity": "INFO",
                "rule": "Unknown process",
                "message": (
                    "Connexion établie sans identifiant de processus "
                    "disponible."
                ),
                "connection": connection,
            })

        # Règle 3 : nombreuses connexions vers une même adresse
        if remote_address in repeated_addresses:
            alerts.append({
                "timestamp": timestamp,
                "severity": "WARNING",
                "rule": "Repeated remote address",
                "message": (
                    f"{address_counts[remote_address]} connexions "
                    f"détectées vers {remote_address}."
                ),
                "connection": connection,
            })

    return alerts