import psutil


def get_network_stats() -> dict:
    """Récupère les statistiques réseau cumulées du PC."""

    stats = psutil.net_io_counters()

    if stats is None:
        return {
            "bytes_sent": 0,
            "bytes_received": 0,
            "packets_sent": 0,
            "packets_received": 0,
        }

    return {
        "bytes_sent": stats.bytes_sent,
        "bytes_received": stats.bytes_recv,
        "packets_sent": stats.packets_sent,
        "packets_received": stats.packets_recv,
    }


def get_network_connections() -> list[dict]:
    """Récupère les connexions réseau visibles depuis Windows."""

    connections = []

    for connection in psutil.net_connections(kind="inet"):

        local_address = (
            f"{connection.laddr.ip}:{connection.laddr.port}"
            if connection.laddr
            else None
        )

        remote_address = (
            f"{connection.raddr.ip}:{connection.raddr.port}"
            if connection.raddr
            else None
        )

        connections.append({
            "protocol": "TCP" if connection.type == 1 else "UDP",
            "local_address": local_address,
            "remote_address": remote_address,
            "status": connection.status,
            "pid": connection.pid,
        })

    return connections