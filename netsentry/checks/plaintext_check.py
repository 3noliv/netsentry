from __future__ import annotations

from typing import Dict

from netsentry.models.types import HostResult, Finding, Severity
from netsentry.rules.loader import Rule


def _build_finding(rule: Rule, details: str, port: int) -> Finding:
    return Finding(
        id=rule.id,
        title=rule.title,
        severity=Severity(rule.severity),
        details=details,
        recommendation=rule.recommendation,
        port=port,
    )


def run_plaintext_checks(host: HostResult, rules: Dict[str, Rule]) -> None:
    """
    Comprueba si el host tiene abiertos puertos típicos de protocolos
    en texto plano (FTP, Telnet) y añade hallazgos si procede.
    """
    for p in host.ports:
        # Telnet
        if p.port == 23 and "TELNET_PLAINTEXT" in rules:
            rule = rules["TELNET_PLAINTEXT"]
            details = (
                f"Puerto Telnet (23/tcp) abierto en {host.ip}. El tráfico viaja sin cifrado."
            )
            host.findings.append(_build_finding(rule, details, port=p.port))

        # FTP
        if p.port == 21 and "FTP_PLAINTEXT" in rules:
            rule = rules["FTP_PLAINTEXT"]
            details = (
                f"Puerto FTP (21/tcp) abierto en {host.ip}. "
                "Credenciales y datos pueden viajar en texto claro."
            )
            host.findings.append(_build_finding(rule, details, port=p.port))

