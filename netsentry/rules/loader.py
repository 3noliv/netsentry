from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional, Any

import yaml


@dataclass
class Rule:
    """
    Representa una regla individual del fichero rules.yaml.
    """
    id: str
    title: str
    severity: str
    recommendation: str
    category: Optional[str] = None
    base_score: Optional[float] = None
    description_template: Optional[str] = None


# Fichero rules.yaml en este mismo directorio
RULES_FILE = Path(__file__).with_name("rules.yaml")


def load_rules(path: Optional[Path] = None) -> Dict[str, Rule]:
    """
    Carga rules.yaml y devuelve un dict:
        { "HTTP_NO_TLS": Rule(...), "FTP_PLAINTEXT": Rule(...), ... }

    Ignora las secciones de pesos (severity_weights, device_type_weights),
    que las usa el motor de scoring por su cuenta.
    """
    fpath = path or RULES_FILE
    raw = yaml.safe_load(fpath.read_text(encoding="utf-8")) or {}

    rules_section: Dict[str, Any] = raw.get("rules", {})

    rules: Dict[str, Rule] = {}
    for rule_id, cfg in rules_section.items():
        rules[rule_id] = Rule(
            id=rule_id,
            title=cfg.get("title", rule_id),
            severity=cfg.get("severity", "INFO"),
            recommendation=cfg.get("recommendation", ""),
            category=cfg.get("category"),
            base_score=cfg.get("base_score"),
            description_template=cfg.get("description_template"),
        )
    return rules

