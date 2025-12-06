from __future__ import annotations

import ipaddress
import json
import uuid
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Tuple, Dict
import webbrowser

import typer
from rich.console import Console
from rich.table import Table

from netsentry.models.types import ScanResult, HostResult
from netsentry.rules import load_rules
from netsentry.rules.loader import Rule
from netsentry.checks import run_http_checks, run_plaintext_checks, run_service_checks
from netsentry.scan.simple_scanner import scan_basic_ports
from netsentry.discovery.ping import ping_host
from netsentry.report.json_export import write_json
from netsentry.report.md_export import write_markdown
from netsentry.report.html_export import write_html

app = typer.Typer(help="NetSentry CLI - descubrimiento y evaluación segura en LAN")
console = Console()


# ---------------------------------------------------------------------
# Helpers internos
# ---------------------------------------------------------------------


def _determine_checks(
    no_http: bool,
    no_plaintext: bool,
    no_iot: bool,
    only_http: bool,
) -> Tuple[bool, bool, bool]:
    """
    Devuelve (do_http, do_plaintext, do_iot) en función de las flags.
    """
    if only_http:
        return True, False, False

    do_http = not no_http
    do_plain = not no_plaintext
    do_iot = not no_iot
    return do_http, do_plain, do_iot


def _find_last_file(directory: Path, pattern: str) -> Optional[Path]:
    """
    Devuelve el fichero más reciente que coincida con el patrón, o None.
    Ejemplo: pattern='results_*.json' o 'report_*.html'
    """
    files = sorted(directory.glob(pattern), key=lambda p: p.stat().st_mtime, reverse=True)
    return files[0] if files else None


def _print_summary(scan: ScanResult) -> None:
    """
    Muestra un resumen de hosts, puertos y hallazgos en formato tabla.
    """
    for host in scan.hosts:
        console.print()
        risk_level = host.risk_level()
        risk_score = host.risk_score()
        device_type = host.device_type()

        console.print(
            f"[bold underline]Host {host.ip}[/bold underline] "
            f"(Tipo: [italic]{device_type}[/italic] | "
            f"Riesgo: [bold]{risk_level}[/bold], Score: {risk_score})"
        )
        if host.hostname:
            console.print(f"Hostname: [italic]{host.hostname}[/italic]")

        # Tabla de puertos
        ports_table = Table(title="Puertos básicos detectados")
        ports_table.add_column("Puerto", justify="right")
        ports_table.add_column("Protocolo")
        ports_table.add_column("Servicio")
        ports_table.add_column("Producto")
        ports_table.add_column("Versión")

        if host.ports:
            for p in host.ports:
                ports_table.add_row(
                    str(p.port),
                    p.protocol,
                    p.service or "-",
                    p.product or "-",
                    p.version or "-",
                )
        else:
            ports_table.add_row("-", "-", "-", "-", "-")

        console.print(ports_table)

        # Tabla de hallazgos
        findings_table = Table(title="Hallazgos")
        findings_table.add_column("ID", style="bold")
        findings_table.add_column("Severidad")
        findings_table.add_column("Puerto")
        findings_table.add_column("Título")
        findings_table.add_column("Detalles")

        if host.findings:
            for f in host.findings:
                findings_table.add_row(
                    f.id,
                    f.severity.value,
                    str(f.port) if f.port is not None else "-",
                    f.title,
                    f.details,
                )
        else:
            findings_table.add_row("-", "-", "-", "Sin hallazgos", "")

        console.print(findings_table)


def _compute_exit_code(scan: ScanResult) -> int:
    """
    Devuelve un código de salida sencillo según el peor nivel de riesgo
    encontrado en los hosts del escaneo.

    - 0 → sin hallazgos o solo INFO
    - 1 → al menos un hallazgo MEDIUM (pero ninguno HIGH)
    - 2 → al menos un hallazgo HIGH
    """
    order = {"NONE": 0, "INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3}
    worst = "NONE"

    for host in scan.hosts:
        level = host.risk_level()
        if order.get(level, 0) > order.get(worst, 0):
            worst = level

    if worst == "HIGH":
        return 2
    if worst == "MEDIUM":
        return 1
    return 0


def _search_pattern_in_results(pattern: str, directory: Path, case_insensitive: bool = True) -> List[Dict]:
    """
    Busca un patrón en todos los ficheros JSON de resultados de 'directory'
    y devuelve una lista de matches con info básica.
    """
    matches: List[Dict] = []

    if case_insensitive:
        pattern_cmp = pattern.lower()
    else:
        pattern_cmp = pattern

    for json_file in directory.glob("results_*.json"):
        try:
            data = json.loads(json_file.read_text(encoding="utf-8"))
        except Exception:
            continue

        scan_id = data.get("scan_id", json_file.name)
        hosts = data.get("hosts", [])

        for host in hosts:
            host_ip = host.get("ip") or host.get("host") or "?"
            findings = host.get("findings", [])

            for f in findings:
                text_fields = [
                    f.get("id", ""),
                    f.get("title", ""),
                    f.get("details", ""),
                    f.get("category", ""),
                    str(f.get("severity", "")),
                ]
                joined = " | ".join(text_fields)

                haystack = joined.lower() if case_insensitive else joined
                if pattern_cmp in haystack:
                    matches.append(
                        {
                            "scan_id": scan_id,
                            "file": json_file.name,
                            "host": host_ip,
                            "id": f.get("id", ""),
                            "severity": f.get("severity", ""),
                            "title": f.get("title", ""),
                        }
                    )

    return matches


# ---------------------------------------------------------------------
# Comando principal: scan
# ---------------------------------------------------------------------


@app.command()
def scan(
    host: Optional[str] = typer.Option(
        None,
        "--host",
        "-H",
        help="Host único a analizar (ej. 192.168.1.10).",
    ),
    network: Optional[str] = typer.Option(
        None,
        "--network",
        "-n",
        help="Rango de red a escanear (ej. 192.168.1.0/24).",
    ),
    outdir: Path = typer.Option(
        Path("out"),
        "--outdir",
        "-o",
        help="Directorio donde guardar resultados (JSON/MD/HTML).",
    ),
    json_only: bool = typer.Option(
        False,
        "--json-only",
        help="Solo genera el JSON (no crea Markdown ni HTML).",
    ),
    no_html: bool = typer.Option(
        False,
        "--no-html",
        help="No generar informe HTML.",
    ),
    no_markdown: bool = typer.Option(
        False,
        "--no-md",
        "--no-markdown",
        help="No generar playbook en Markdown.",
    ),
    quiet: bool = typer.Option(
        False,
        "--quiet",
        "-q",
        help="Modo silencioso: no mostrar resumen detallado en consola.",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Modo detallado: muestra información ampliada durante el escaneo.",
    ),
    no_http: bool = typer.Option(
        False,
        "--no-http",
        help="No ejecutar comprobaciones HTTP/HTTPS.",
    ),
    no_plaintext: bool = typer.Option(
        False,
        "--no-plaintext",
        help="No ejecutar comprobaciones de protocolos en texto claro (Telnet/FTP).",
    ),
    no_iot: bool = typer.Option(
        False,
        "--no-iot",
        help="No ejecutar comprobaciones de servicios IoT/SMB (MQTT/RTSP/UPnP/SMB).",
    ),
    only_http: bool = typer.Option(
        False,
        "--only-http",
        help="Solo ejecutar comprobaciones HTTP/HTTPS (ignora otros checks).",
    ),
) -> None:
    """
    Ejecuta un escaneo de host o red y genera resultados en JSON
    (y opcionalmente Markdown + HTML).
    """
    if not host and not network:
        raise typer.BadParameter("Debes indicar --host o --network.")

    # Aseguramos que el directorio de salida exista
    outdir.mkdir(parents=True, exist_ok=True)

    scan_id = uuid.uuid4().hex[:8]
    started_at = datetime.now()

    if network:
        console.rule(f"[bold cyan]sentry scan[/bold cyan] (network={network})")
    else:
        console.rule(f"[bold cyan]sentry scan[/bold cyan] (host={host})")

    console.print("[bold]Cargando reglas.[/bold]")
    rules = load_rules()

    hosts_results: List[HostResult] = []

    do_http, do_plain, do_iot = _determine_checks(no_http, no_plaintext, no_iot, only_http)

    # --- Modo host único ---
    if host:
        console.print(f"[bold]Escaneando host {host}.[/bold]")
        host_result = scan_basic_ports(host)

        if verbose:
            if host_result.ports:
                ports_str = ", ".join(
                    f"{p.port}/{p.protocol} ({p.service or '?'})" for p in host_result.ports
                )
            else:
                ports_str = "sin puertos básicos abiertos"
            console.print(f"[dim]Puertos detectados en {host}: {ports_str}[/dim]")

        if do_http:
            console.print("[bold]Ejecutando comprobaciones HTTP/HTTPS.[/bold]")
            run_http_checks(host_result, rules)
        elif verbose:
            console.print("[dim]Saltando comprobaciones HTTP/HTTPS (flags).[/dim]")

        if do_plain:
            console.print("[bold]Ejecutando comprobaciones de protocolos en texto plano.[/bold]")
            run_plaintext_checks(host_result, rules)
        elif verbose:
            console.print("[dim]Saltando comprobaciones de protocolos en texto plano (flags).[/dim]")

        if do_iot:
            console.print("[bold]Ejecutando comprobaciones de servicios IoT/SMB.[/bold]")
            run_service_checks(host_result, rules)
        elif verbose:
            console.print("[dim]Saltando comprobaciones de servicios IoT/SMB (flags).[/dim]")

        hosts_results.append(host_result)

    # --- Modo red completa ---
    if network:
        console.print(f"[bold]Escaneando red {network} (ping + puertos básicos).[/bold]")
        try:
            net = ipaddress.ip_network(network, strict=False)
        except ValueError as e:
            raise typer.BadParameter(f"Rango de red inválido: {e}")

        for ip in net.hosts():
            ip_str = str(ip)
            console.print(f"[dim]- Pinging {ip_str}[/dim]", end="")
            alive = ping_host(ip_str, timeout_ms=300)

            if not alive:
                console.print(" [red]no responde[/red]")
                continue

            console.print(" [green]vivo[/green]  → escaneando puertos.")
            host_result = scan_basic_ports(ip_str)

            if verbose:
                if host_result.ports:
                    ports_str = ", ".join(
                        f"{p.port}/{p.protocol} ({p.service or '?'})" for p in host_result.ports
                    )
                else:
                    ports_str = "sin puertos básicos abiertos"
                console.print(f"[dim]Puertos detectados en {ip_str}: {ports_str}[/dim]")

            if do_http:
                console.print("[bold]Ejecutando comprobaciones HTTP/HTTPS.[/bold]")
                run_http_checks(host_result, rules)
            elif verbose:
                console.print("[dim]Saltando comprobaciones HTTP/HTTPS (flags).[/dim]")

            if do_plain:
                console.print("[bold]Ejecutando comprobaciones de protocolos en texto plano.[/bold]")
                run_plaintext_checks(host_result, rules)
            elif verbose:
                console.print(
                    "[dim]Saltando comprobaciones de protocolos en texto plano (flags).[/dim]"
                )

            if do_iot:
                console.print("[bold]Ejecutando comprobaciones de servicios IoT/SMB.[/bold]")
                run_service_checks(host_result, rules)
            elif verbose:
                console.print("[dim]Saltando comprobaciones de servicios IoT/SMB (flags).[/dim]")

            hosts_results.append(host_result)

    finished_at = datetime.now()

    scan_result = ScanResult(
        scan_id=scan_id,
        network=network,
        hosts=hosts_results,
        started_at=started_at,
        finished_at=finished_at,
        metadata={"mode": "network" if network else "host", "target": host or network},
    )

    # 3) Mostrar resumen por consola (a no ser que pidan quiet)
    if not quiet:
        _print_summary(scan_result)

    # 4) Exportar resultados
    json_path = write_json(scan_result, outdir)

    md_path = None
    html_path = None

    if not json_only and not no_markdown:
        md_path = write_markdown(scan_result, outdir)
    if not json_only and not no_html:
        html_path = write_html(scan_result, outdir)

    if not quiet:
        console.print()
        console.print(f"[green]JSON guardado en:[/green] {json_path}")
        if md_path is not None:
            console.print(f"[green]Markdown guardado en:[/green] {md_path}")
        if html_path is not None:
            console.print(f"[green]HTML guardado en:[/green] {html_path}")

        console.print()
        console.rule("[bold green]Fin del escaneo[/bold green]")

    # 5) Código de salida según nivel de riesgo
    exit_code = _compute_exit_code(scan_result)
    raise typer.Exit(code=exit_code)


# ---------------------------------------------------------------------
# Comando: report → generar HTML/MD a partir de un JSON previo
# ---------------------------------------------------------------------


@app.command()
def report(
    input: Path = typer.Option(
        ...,
        "--input",
        "-i",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
        help="Fichero JSON de resultados (results_*.json) del que generar informes.",
    ),
    outdir: Path = typer.Option(
        Path("out"),
        "--outdir",
        "-o",
        help="Directorio donde guardar los informes generados.",
    ),
    no_html: bool = typer.Option(
        False,
        "--no-html",
        help="No generar informe HTML.",
    ),
    no_markdown: bool = typer.Option(
        False,
        "--no-md",
        "--no-markdown",
        help="No generar playbook en Markdown.",
    ),
    quiet: bool = typer.Option(
        False,
        "--quiet",
        "-q",
        help="Modo silencioso: no mostrar resumen en consola.",
    ),
) -> None:
    """
    Genera Markdown/HTML a partir de un JSON previo (no realiza escaneo).
    """
    outdir.mkdir(parents=True, exist_ok=True)

    data = json.loads(input.read_text(encoding="utf-8"))
    scan_result = ScanResult.model_validate(data)

    md_path = None
    html_path = None

    if not no_markdown:
        md_path = write_markdown(scan_result, outdir)
    if not no_html:
        html_path = write_html(scan_result, outdir)

    if not quiet:
        _print_summary(scan_result)

        console.print()
        if md_path is not None:
            console.print(f"[green]Markdown guardado en:[/green] {md_path}")
        if html_path is not None:
            console.print(f"[green]HTML guardado en:[/green] {html_path}")

        console.print()
        console.rule("[bold green]Fin de la generación de informes[/bold green]")


# ---------------------------------------------------------------------
# Comando: summary → mostrar resumen del último JSON (o uno concreto)
# ---------------------------------------------------------------------


@app.command()
def summary(
    input: Optional[Path] = typer.Option(
        None,
        "--input",
        "-i",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
        help="Fichero JSON de resultados concreto. Si se omite, usa el último results_*.json en --outdir.",
    ),
    outdir: Path = typer.Option(
        Path("out"),
        "--outdir",
        "-o",
        help="Directorio donde buscar el JSON si no se indica --input.",
    ),
) -> None:
    """
    Muestra un resumen en consola a partir de un JSON (último por defecto).
    """
    if input is None:
        last = _find_last_file(outdir, "results_*.json")
        if last is None:
            console.print("[red]No se ha encontrado ningún results_*.json en el directorio indicado.[/red]")
            raise typer.Exit(code=1)
        input = last

    data = json.loads(input.read_text(encoding="utf-8"))
    scan_result = ScanResult.model_validate(data)

    console.rule(f"[bold cyan]Resumen de {input.name}[/bold cyan]")
    _print_summary(scan_result)
    console.print()
    console.rule("[bold green]Fin del resumen[/bold green]")


# ---------------------------------------------------------------------
# Comando: open-last → abrir el último HTML en el navegador
# ---------------------------------------------------------------------


@app.command("open-last")
def open_last(
    outdir: Path = typer.Option(
        Path("out"),
        "--outdir",
        "-o",
        help="Directorio donde buscar el último HTML (report_*.html).",
    ),
) -> None:
    """
    Abre en el navegador el último informe HTML generado.
    """
    last_html = _find_last_file(outdir, "report_*.html")
    if last_html is None:
        console.print("[red]No se ha encontrado ningún report_*.html en el directorio indicado.[/red]")
        raise typer.Exit(code=1)

    console.print(f"[green]Abriendo {last_html} en el navegador...[/green]")
    webbrowser.open(last_html.resolve().as_uri())
    raise typer.Exit(code=0)


# ---------------------------------------------------------------------
# Comando: find → buscar un patrón en todos los JSON de resultados
# ---------------------------------------------------------------------


@app.command()
def find(
    pattern: str = typer.Argument(
        ...,
        help="Patrón a buscar en los hallazgos (ID, título, detalles, categoría, severidad).",
    ),
    outdir: Path = typer.Option(
        Path("out"),
        "--outdir",
        "-o",
        help="Directorio donde buscar ficheros results_*.json.",
    ),
    case_insensitive: bool = typer.Option(
        True,
        "--ignore-case/--case-sensitive",
        help="Búsqueda sin distinguir mayúsculas/minúsculas (por defecto activado).",
    ),
) -> None:
    """
    Busca un patrón en todos los ficheros JSON de resultados y muestra un resumen
    de los hallazgos coincidentes.
    """
    matches = _search_pattern_in_results(pattern, outdir, case_insensitive=case_insensitive)

    if not matches:
        console.print("[yellow]No se han encontrado coincidencias.[/yellow]")
        raise typer.Exit(code=0)

    table = Table(title=f"Coincidencias para '{pattern}'")
    table.add_column("Scan ID")
    table.add_column("Fichero")
    table.add_column("Host")
    table.add_column("ID")
    table.add_column("Severidad")
    table.add_column("Título")

    for m in matches:
        table.add_row(
            m["scan_id"],
            m["file"],
            m["host"],
            m["id"],
            str(m["severity"]),
            m["title"],
        )

    console.print(table)
    raise typer.Exit(code=0)

