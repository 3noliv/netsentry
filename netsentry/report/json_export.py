from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

from netsentry.models.types import ScanResult
from netsentry.rules.rules_engine import RulesEngine


def _serialize_scan(scan: ScanResult) -> Dict[str, Any]:
    """
    Convierte ScanResult en un dict listo para volcarse a JSON,
    incluyendo el bloque de 'scoring' calculado con RulesEngine.
    """

    # -----------------------
    # 1) Estructura básica (igual que antes)
    # -----------------------
    hosts_data: List[Dict[str, Any]] = []

    for host in scan.hosts:
        ports_data: List[Dict[str, Any]] = []
        for p in host.ports:
            ports_data.append(
                {
                    "port": p.port,
                    "protocol": p.protocol,
                    "service": p.service,
                    "product": p.product,
                    "version": p.version,
                }
            )

        findings_data: List[Dict[str, Any]] = []
        for f in host.findings:
            findings_data.append(
                {
                    "id": f.id,
                    "severity": f.severity.value,
                    "port": f.port,
                    "title": f.title,
                    "details": f.details,
                    "recommendation": f.recommendation,
                }
            )

        hosts_data.append(
            {
                "ip": host.ip,
                "hostname": host.hostname,
                "ports": ports_data,
                "findings": findings_data,
            }
        )

    base_data: Dict[str, Any] = {
        "scan_id": scan.scan_id,
        "network": scan.network,
        "hosts": hosts_data,
        "started_at": scan.started_at.isoformat(),
        "finished_at": scan.finished_at.isoformat(),
        "metadata": scan.metadata or {},
    }

    # -----------------------
    # 2) Cálculo del scoring avanzado
    # -----------------------
    engine = RulesEngine()

    hosts_issues: Dict[str, List[str]] = {}
    devices_types: Dict[str, str] = {}

    # Opcional: extras_by_host_issue si más adelante quieres meter info extra
    extras_by_host_issue: Dict[str, Dict[str, Dict[str, Any]]] = {}

    for host in scan.hosts:
        issue_ids = [f.id for f in host.findings]
        hosts_issues[host.ip] = issue_ids

        # Usamos tu fingerprinting actual
        devices_types[host.ip] = host.device_type()

        # Aquí podríamos rellenar extras (por ejemplo, URL HTTP) si lo necesitas más adelante
        extras_by_host_issue[host.ip] = {}

    scan_score = engine.score_scan(
        scan_id=scan.scan_id,
        hosts_issues=hosts_issues,
        devices_types=devices_types,
        extras_by_host_issue=extras_by_host_issue,
    )
    scoring_dict = RulesEngine.scan_score_to_dict(scan_score)

    base_data["scoring"] = scoring_dict

    return base_data


def write_json(scan: ScanResult, outdir: Path) -> Path:
    """
    Escribe el resultado del escaneo en un archivo JSON.
    """
    outdir.mkdir(parents=True, exist_ok=True)
    fname = f"results_{scan.scan_id}.json"
    outpath = outdir / fname

    data = _serialize_scan(scan)

    with outpath.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    return outpath

