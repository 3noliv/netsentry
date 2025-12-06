# netsentry/checks/service_check.py
from __future__ import annotations

import socket
from typing import Dict, Optional

from netsentry.models.types import HostResult, Finding, Severity
from netsentry.rules.loader import Rule


def _build_finding(
    rule: Rule,
    details: str,
    port: Optional[int] = None,
) -> Finding:
    """
    Construye un Finding sencillo a partir de una regla del YAML.
    """
    return Finding(
        id=rule.id,
        title=rule.title,
        severity=Severity(rule.severity),
        details=details,
        recommendation=rule.recommendation,
        port=port,
    )


def _check_smb(host: HostResult, rules: Dict[str, Rule]) -> None:
    """
    Marca SMB abierto si detectamos el puerto 445/tcp.
    No intentamos enumerar shares (modo safe).
    """
    if "SMB-OPEN" not in rules:
        return

    for p in host.ports:
        if p.port == 445:
            rule = rules["SMB-OPEN"]
            details = (
                f"Puerto SMB (445/tcp) abierto en {host.ip}. "
                "Podría haber recursos compartidos accesibles desde la red."
            )
            host.findings.append(_build_finding(rule, details, port=p.port))
            # con uno nos vale
            break


def _check_mqtt(host: HostResult, rules: Dict[str, Rule]) -> None:
    """
    Detección muy ligera de broker MQTT en 1883/tcp.

    No hacemos handshake completo ni publicamos nada: solo comprobamos
    si el puerto acepta conexión TCP (modo safe).
    """
    if "MQTT-ANON-ACCESS" not in rules:
        return

    has_mqtt_port = any(p.port == 1883 for p in host.ports)
    if not has_mqtt_port:
        return

    # Intento muy corto de conexión TCP
    try:
        with socket.create_connection((host.ip, 1883), timeout=1.5):
            tcp_ok = True
    except OSError:
        tcp_ok = False

    if tcp_ok:
        rule = rules["MQTT-ANON-ACCESS"]
        details = (
            f"Posible broker MQTT accesible en {host.ip}:1883. "
            "Revisa si permite conexión anónima o sin TLS."
        )
        host.findings.append(_build_finding(rule, details, port=1883))


def _check_rtsp(host: HostResult, rules: Dict[str, Rule]) -> None:
    """
    Marca posible servidor RTSP si vemos 554/tcp abierto.

    No enviamos peticiones con credenciales para mantener el modo safe.
    """
    if "RTSP-NO-AUTH" not in rules:
        return

    for p in host.ports:
        if p.port == 554:
            rule = rules["RTSP-NO-AUTH"]
            details = (
                f"Posible servidor RTSP (cámara IP / streaming) en {host.ip}:{p.port}. "
                "Comprueba que el acceso al vídeo requiera autenticación."
            )
            host.findings.append(_build_finding(rule, details, port=p.port))
            break


def _check_upnp_ssdp(host: HostResult, rules: Dict[str, Rule]) -> None:
    """
    Pequeño probe SSDP (UPnP) vía UDP/1900 contra el host concreto.

    No hacemos multicast a toda la red, solo un M-SEARCH directo al host
    para minimizar ruido.
    """
    if "UPNP-SSDP-EXPOSED" not in rules:
        return

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.settimeout(1.5)

        msg = "\r\n".join(
            [
                "M-SEARCH * HTTP/1.1",
                f"HOST: {host.ip}:1900",
                'MAN: "ssdp:discover"',
                "MX: 1",
                "ST: ssdp:all",
                "",
                "",
            ]
        ).encode("utf-8")

        # Enviamos el M-SEARCH al puerto 1900 del host
        sock.sendto(msg, (host.ip, 1900))

        data, _ = sock.recvfrom(2048)
    except socket.timeout:
        return
    except OSError:
        return
    finally:
        try:
            sock.close()
        except Exception:
            pass

    text = data.decode(errors="ignore")
    if not text:
        return

    # Heurística muy sencilla para decidir si parece respuesta SSDP
    lower = text.lower()
    if "upnp:" in lower or "ssdp" in lower or "rootdevice" in lower:
        rule = rules["UPNP-SSDP-EXPOSED"]
        first_line = text.splitlines()[0] if text.splitlines() else ""
        details = (
            f"Respuesta SSDP desde {host.ip}: '{first_line[:120]}'. "
            "Parece que UPnP está expuesto en la red."
        )
        host.findings.append(_build_finding(rule, details, port=None))


def run_service_checks(host: HostResult, rules: Dict[str, Rule]) -> None:
    """
    Orquesta los checks de servicios IoT/SMB sobre un host ya escaneado.

    - SMB en 445/tcp
    - MQTT en 1883/tcp
    - RTSP en 554/tcp
    - UPnP/SSDP en 1900/udp
    """
    _check_smb(host, rules)
    _check_mqtt(host, rules)
    _check_rtsp(host, rules)
    _check_upnp_ssdp(host, rules)

