from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

from jinja2 import Environment, FileSystemLoader, select_autoescape

from netsentry.models.types import ScanResult
from netsentry.rules.rules_engine import RulesEngine


def _build_scoring_context(scan: ScanResult) -> Dict[str, Any]:
    """
    Calcula el scoring avanzado a partir de ScanResult usando RulesEngine
    y devuelve un dict listo para enviar a Jinja.
    """
    engine = RulesEngine()

    hosts_issues: Dict[str, List[str]] = {}
    devices_types: Dict[str, str] = {}
    extras_by_host_issue: Dict[str, Dict[str, Dict[str, Any]]] = {}

    for host in scan.hosts:
        issue_ids = [f.id for f in host.findings]
        hosts_issues[host.ip] = issue_ids
        devices_types[host.ip] = host.device_type()
        extras_by_host_issue[host.ip] = {}

    scan_score = engine.score_scan(
        scan_id=scan.scan_id,
        hosts_issues=hosts_issues,
        devices_types=devices_types,
        extras_by_host_issue=extras_by_host_issue,
    )
    scoring_dict = RulesEngine.scan_score_to_dict(scan_score)
    return scoring_dict


def write_html(scan: ScanResult, outdir: Path) -> Path:
    """
    Genera un informe HTML usando Jinja2 a partir de ScanResult y del scoring avanzado.
    """
    outdir.mkdir(parents=True, exist_ok=True)
    fname = f"report_{scan.scan_id}.html"
    outpath = outdir / fname

    # Directorio de templates: netsentry/report/templates
    templates_dir = Path(__file__).parent / "templates"

    env = Environment(
        loader=FileSystemLoader(str(templates_dir)),
        autoescape=select_autoescape(["html", "xml"]),
    )

    template = env.get_template("report.html.j2")

    scoring = _build_scoring_context(scan)

    html = template.render(
        scan=scan,
        scoring=scoring,
        generated_at=datetime.now().isoformat(timespec="seconds"),
    )

    outpath.write_text(html, encoding="utf-8")
    return outpath

