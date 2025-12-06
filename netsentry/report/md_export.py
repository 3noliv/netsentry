from __future__ import annotations

from datetime import datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from netsentry.models.types import ScanResult


def _build_env(template_dir: Path) -> Environment:
    return Environment(
        loader=FileSystemLoader(str(template_dir)),
        autoescape=select_autoescape(["html", "xml"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )


def write_markdown(scan: ScanResult, outdir: Path) -> Path:
    """
    Genera un reporte Markdown a partir de ScanResult usando Jinja2.
    Busca la plantilla 'report.md.j2' en netsentry/report/templates.
    """
    outdir.mkdir(parents=True, exist_ok=True)

    base_dir = Path(__file__).resolve().parent
    template_dir = base_dir / "templates"
    env = _build_env(template_dir)

    template = env.get_template("report.md.j2")

    content = template.render(
        scan=scan,
        generated_at=datetime.now().isoformat(timespec="seconds"),
    )

    filename = f"report_{scan.scan_id}.md"
    path = outdir / filename

    with path.open("w", encoding="utf-8") as f:
        f.write(content)

    return path

