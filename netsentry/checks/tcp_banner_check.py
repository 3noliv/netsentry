from __future__ import annotations

import socket
from typing import Iterable

from netsentry.models.types import HostResult


# Puertos típicos donde los banners son muy útiles
BANNER_PORTS = {
    21,   # FTP
    22,   # SSH
    23,   # Telnet
    25,   # SMTP
    110,  # POP3
    143,  # IMAP
    3389, # RDP
    5900, # VNC
}


def _iter_ports_candidate(host: HostResult) -> Iterable[int]:
    """
    Devuelve puertos candidatos para banner grabbing,
    excluyendo los que ya están identificados como HTTP/HTTPS
    o que ya tienen product asignado.
    """
    for p in host.ports:
        if p.product:
            # Ya hemos rellenado product (por ejemplo, enrich_http_banners)
            continue

        service = (p.service or "").lower()
        if service in ("http", "https"):
            # HTTP/HTTPS ya los tratamos en enrich_http_banners
            continue

        if p.port in BANNER_PORTS:
            yield p.port


def grab_tcp_banners(host: HostResult) -> None:
    """
    Intenta obtener banners TCP de servicios típicos (SSH, FTP, Telnet, etc.)
    y los vuelca en PortInfo.product. No genera hallazgos, solo información.
    """
    for port in _iter_ports_candidate(host):
        banner = _grab_banner_once(host.ip, port)
        if not banner:
            continue

        # Buscamos el objeto PortInfo correspondiente y rellenamos product
        for p in host.ports:
            if p.port == port and not p.product:
                # Guardamos el banner recortado (para que no sea infinito)
                p.product = banner[:80].strip()
                # Si quisieras, aquí podrías intentar parsear versión a p.version
                break


def _grab_banner_once(ip: str, port: int) -> str | None:
    """
    Conecta al puerto TCP y lee un pequeño banner (hasta 1 KB).
    Devuelve None si no hay o falla.
    """
    s = None
    try:
        s = socket.create_connection((ip, port), timeout=2.0)
        s.settimeout(2.0)
        data = s.recv(1024)
    except OSError:
        return None
    finally:
        if s is not None:
            try:
                s.close()
            except Exception:
                pass

    if not data:
        return None

    return data.decode(errors="ignore")

