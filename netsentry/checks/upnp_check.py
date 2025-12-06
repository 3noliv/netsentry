from __future__ import annotations

import socket
from typing import Dict

from netsentry.models.types import HostResult, Finding, Severity
from netsentry.rules.loader import Rule


def run_upnp_ssdp_check(host: HostResult, rules: Dict[str, Rule]) -> None:
    """
    Lanza un probe SSDP (UPnP) al host (puerto 1900/UDP).
    Si responde algo que parece UPnP/SSDP, genera el hallazgo UPNP-SSDP-EXPOSED.
    """
    if "UPNP-SSDP-EXPOSED" not in rules:
        return

    rule: Rule = rules["UPNP-SSDP-EXPOSED"]

    # Construimos un M-SEARCH básico (formato estándar SSDP).
    msg = (
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        "MAN: \"ssdp:discover\"\r\n"
        "MX: 1\r\n"
        "ST: ssdp:all\r\n"
        "\r\n"
    )

    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1.5)

        # Enviamos el M-SEARCH directamente al host en el puerto 1900/UDP.
        sock.sendto(msg.encode("utf-8"), (host.ip, 1900))

        data, addr = sock.recvfrom(65535)
    except (socket.timeout, OSError):
        # Si no hay respuesta o hay error de red, asumimos que no hay UPnP accesible.
        return
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass

    if not data:
        return

    lower = data.decode(errors="ignore").lower()

    # Heurística muy básica para considerar que es una respuesta UPnP/SSDP.
    if "upnp:" in lower or "ssdp:" in lower or "rootdevice" in lower or "urn:" in lower:
        details = rule.description_template.format(host=host.ip)
        finding = Finding(
            id=rule.id,
            title=rule.title,
            severity=Severity(rule.severity),
            details=details,
            recommendation=rule.recommendation,
            port=1900,  # aunque sea UDP, lo marcamos como 1900
        )
        host.findings.append(finding)

