from __future__ import annotations

from typing import Dict

from netsentry.models.types import HostResult, Finding, Severity
from netsentry.rules.loader import Rule


def run_fingerprint_check(host: HostResult, rules: Dict[str, Rule]) -> None:
    """
    Añade un hallazgo informativo con el tipo de dispositivo detectado.
    """
    if "INFO-DEVICE-FINGERPRINT" not in rules:
        return

    rule: Rule = rules["INFO-DEVICE-FINGERPRINT"]
    device_type = host.device_type()

    details = rule.description_template.format(
        host=host.ip,
        device_type=device_type,
    )

    host.findings.append(
        Finding(
            id=rule.id,
            title=rule.title,
            severity=Severity(rule.severity),
            details=details,
            recommendation=rule.recommendation,
            port=None,
        )
    )

