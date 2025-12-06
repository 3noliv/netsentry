from __future__ import annotations

import socket
from typing import List

from netsentry.models.types import HostResult, PortInfo

# Puertos típicos a comprobar en el MVP
HTTP_PORTS = [80, 8080]
HTTPS_PORTS = [443, 8443]
FTP_PORTS = [21]
TELNET_PORTS = [23]

ALL_PORTS = HTTP_PORTS + HTTPS_PORTS + FTP_PORTS + TELNET_PORTS


def _is_port_open(host: str, port: int, timeout: float = 0.3) -> bool:
    """
    Intenta conectar por TCP al puerto indicado para ver si está abierto.
    No envía datos, solo hace un connect() rápido.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        return True
    except OSError:
        return False
    finally:
        try:
            s.close()
        except Exception:
            pass


def scan_basic_ports(host_ip: str) -> HostResult:
    """
    Escanea puertos básicos (HTTP/HTTPS/FTP/Telnet) en un host y devuelve
    un HostResult con la lista de puertos abiertos.
    """
    ports: List[PortInfo] = []

    for port in ALL_PORTS:
        if _is_port_open(host_ip, port):
            service = None
            if port in HTTP_PORTS:
                service = "http"
            elif port in HTTPS_PORTS:
                service = "https"
            elif port in FTP_PORTS:
                service = "ftp"
            elif port in TELNET_PORTS:
                service = "telnet"

            ports.append(
                PortInfo(
                    port=port,
                    protocol="tcp",
                    service=service,
                )
            )

    return HostResult(ip=host_ip, ports=ports)

