# sentry/rules_engine.py

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional
import pathlib
import yaml


# -----------------------------
# Modelos de datos
# -----------------------------

@dataclass
class FindingRule:
    id: str
    title: str
    category: str
    severity: str
    base_score: int
    description_template: str
    recommendation: str


@dataclass
class Finding:
    id: str
    title: str
    category: str
    severity: str
    score: float
    details: str
    recommendation: str
    extra: Dict[str, Any] = field(default_factory=dict)


@dataclass
class HostScore:
    host: str
    device_type: str
    findings: List[Finding]
    total_score: float
    # NUEVO: breakdown por categoría (CIFRADO, AUTENTICACION, CONFIG_ROUTER, etc.)
    categories: Dict[str, float] = field(default_factory=dict)


@dataclass
class ScanScore:
    scan_id: str
    hosts: List[HostScore]
    total_score: float
    # NUEVO: breakdown global por categoría en todo el escaneo
    categories: Dict[str, float] = field(default_factory=dict)


# -----------------------------
# Carga de reglas
# -----------------------------

class RulesEngine:
    def __init__(self, rules_path: Optional[str] = None) -> None:
        if rules_path is None:
            # por defecto: rules.yaml al lado de este archivo
            rules_path = pathlib.Path(__file__).with_name("rules.yaml")
        self.rules_path = pathlib.Path(rules_path)

        self.severity_weights: Dict[str, int] = {}
        self.device_type_weights: Dict[str, float] = {}
        self.rules: Dict[str, FindingRule] = {}

        self._load()

    def _load(self) -> None:
        with self.rules_path.open("r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        self.severity_weights = {
            k.upper(): int(v) for k, v in data.get("severity_weights", {}).items()
        }
        self.device_type_weights = {
            k.lower(): float(v) for k, v in data.get("device_type_weights", {}).items()
        }

        rules_data = data.get("rules", {})
        for issue_id, rule_cfg in rules_data.items():
            rule = FindingRule(
                id=issue_id,
                title=rule_cfg["title"],
                category=rule_cfg["category"],
                severity=rule_cfg["severity"].upper(),
                base_score=int(rule_cfg.get("base_score", 0)),
                description_template=rule_cfg.get("description_template", ""),
                recommendation=rule_cfg.get("recommendation", ""),
            )
            self.rules[issue_id] = rule

    # -----------------------------
    # Helpers internos
    # -----------------------------

    def _normalise_device_type_key(self, device_type: str) -> str:
        """
        Convierte la descripción libre del device_type (p.ej. "Router / CPE")
        en una clave estándar para usar con device_type_weights:
          router, camera, nas, iot, pc, unknown
        """
        dt = (device_type or "").lower()

        if "router" in dt or "cpe" in dt or "gateway" in dt:
            return "router"
        if "cámara" in dt or "camara" in dt or "camera" in dt or "ip / vídeo" in dt or "video" in dt:
            return "camera"
        if "nas" in dt or "almacenamiento" in dt or "storage" in dt:
            return "nas"
        if "iot" in dt:
            return "iot"
        if "windows" in dt or "pc" in dt or "servidor" in dt:
            return "pc"
        return "unknown"

    # -----------------------------
    # Aplicación de reglas
    # -----------------------------

    def create_finding(
        self,
        issue_id: str,
        host: str,
        device_type: str = "unknown",
        extra: Optional[Dict[str, Any]] = None,
    ) -> Optional[Finding]:
        """
        Crea un Finding a partir de un issue_id + contexto (host, device_type, extra).
        Devuelve None si no existe regla para ese issue_id.
        """
        rule = self.rules.get(issue_id)
        if rule is None:
            return None

        extra = extra or {}

        # Construimos la descripción usando la plantilla
        details = rule.description_template.format(
            host=host,
            device_type=device_type,
            **extra,
        )

        # Score base según severidad + base_score
        sev_weight = self.severity_weights.get(rule.severity.upper(), 0)
        base = rule.base_score + sev_weight

        # Factor por tipo de dispositivo (normalizado)
        dev_key = self._normalise_device_type_key(device_type)
        dev_factor = self.device_type_weights.get(dev_key, 1.0)

        score = base * dev_factor

        return Finding(
            id=rule.id,
            title=rule.title,
            category=rule.category,
            severity=rule.severity,
            score=score,
            details=details,
            recommendation=rule.recommendation,
            extra=extra,
        )

    def score_host(
        self,
        host: str,
        issue_ids: List[str],
        device_type: str = "unknown",
        extras_by_issue: Optional[Dict[str, Dict[str, Any]]] = None,
    ) -> HostScore:
        """
        Recibe una lista de issue_ids detectados para un host y devuelve:
        - Findings generados
        - Score total del host
        - Breakdown por categoría
        """
        extras_by_issue = extras_by_issue or {}

        findings: List[Finding] = []
        total_score = 0.0
        categories: Dict[str, float] = {}

        for issue_id in issue_ids:
            extra = extras_by_issue.get(issue_id, {})
            finding = self.create_finding(
                issue_id=issue_id,
                host=host,
                device_type=device_type,
                extra=extra,
            )
            if finding is None:
                continue
            findings.append(finding)
            total_score += finding.score

            # Acumulamos por categoría
            cat = finding.category or "OTROS"
            categories[cat] = categories.get(cat, 0.0) + finding.score

        return HostScore(
            host=host,
            device_type=device_type,
            findings=findings,
            total_score=total_score,
            categories=categories,
        )

    def score_scan(
        self,
        scan_id: str,
        hosts_issues: Dict[str, List[str]],
        devices_types: Optional[Dict[str, str]] = None,
        extras_by_host_issue: Optional[Dict[str, Dict[str, Dict[str, Any]]]] = None,
    ) -> ScanScore:
        """
        Calcula el score global de un scan.

        hosts_issues: { "192.168.1.10": ["TELNET-OPEN", "HTTP-NO-TLS"], ... }
        devices_types: { "192.168.1.10": "router", "192.168.1.20": "camera" }
        extras_by_host_issue:
          {
            "192.168.1.10": {
              "HTTP-NO-TLS": {"url": "http://192.168.1.10"},
              ...
            },
            ...
          }
        """
        devices_types = devices_types or {}
        extras_by_host_issue = extras_by_host_issue or {}

        host_scores: List[HostScore] = []
        total = 0.0
        global_categories: Dict[str, float] = {}

        for host, issues in hosts_issues.items():
            device_type = devices_types.get(host, "unknown")
            host_extras = extras_by_host_issue.get(host, {})
            host_score = self.score_host(
                host=host,
                issue_ids=issues,
                device_type=device_type,
                extras_by_issue=host_extras,
            )
            host_scores.append(host_score)
            total += host_score.total_score

            # Acumulamos categorías globales
            for cat, val in host_score.categories.items():
                global_categories[cat] = global_categories.get(cat, 0.0) + val

        return ScanScore(
            scan_id=scan_id,
            hosts=host_scores,
            total_score=total,
            categories=global_categories,
        )

    # -----------------------------
    # Helpers para serializar
    # -----------------------------

    @staticmethod
    def scan_score_to_dict(scan_score: ScanScore) -> Dict[str, Any]:
        """
        Convierte el objeto ScanScore en un dict listo para volcar a JSON.
        """
        return {
            "scan_id": scan_score.scan_id,
            "total_score": scan_score.total_score,
            # NUEVO: categorías globales del escaneo
            "categories": scan_score.categories,
            "hosts": [
                {
                    "host": h.host,
                    "device_type": h.device_type,
                    "total_score": h.total_score,
                    # NUEVO: categorías por host
                    "categories": h.categories,
                    "findings": [asdict(f) for f in h.findings],
                }
                for h in scan_score.hosts
            ],
        }

