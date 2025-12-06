from __future__ import annotations

from typing import Dict, Optional

import requests

from netsentry.models.types import HostResult, Severity  # Severity no se usa aún, pero puede servir luego


DEFAULT_TIMEOUT = 3
DEFAULT_USER_AGENT = "NetSentry-CLI/0.1"


def _parse_server_header(server_header: str) -> tuple[Optional[str], Optional[str]]:
    """
    Intenta separar el header Server en (producto, versión) de forma sencilla.
    Ejemplos:
      - "nginx/1.18.0 (Ubuntu)" -> ("nginx", "1.18.0")
      - "Apache/2.4.54 (Debian)" -> ("Apache", "2.4.54")
      - "MikroTik http proxy"    -> ("MikroTik http proxy", None)
    """
    if not server_header:
        return None, None

    # Nos quedamos con la primera "parte" antes del paréntesis, si existe.
    main = server_header.split("(", 1)[0].strip()

    # Si hay algo tipo "nombre/x.y.z", intentamos separar por "/"
    if "/" in main:
        prod, ver = main.split("/", 1)
        prod = prod.strip() or None
        ver = ver.strip() or None
        return prod, ver

    # Si no hay "/", dejamos todo como producto y sin versión
    return main or None, None


def enrich_http_banners(host: HostResult) -> None:
    """
    Para cada puerto HTTP/HTTPS del host, intenta obtener el header Server
    y lo vuelca en PortInfo.product / PortInfo.version.
    No genera hallazgos, solo enriquece la información.
    """
    for p in host.ports:
        service = (p.service or "").lower()

        # Heurística para considerar que es HTTP/HTTPS
        is_httpish = (
            service in ("http", "https")
            or p.port in (80, 8080, 8000)
            or (p.port == 443 and service != "ssh")  # 443 casi siempre es HTTPS
        )

        if not is_httpish:
            continue

        scheme = "https" if (service == "https" or p.port == 443) else "http"
        url = f"{scheme}://{host.ip}:{p.port}"

        try:
            resp = requests.head(
                url,
                headers={"User-Agent": DEFAULT_USER_AGENT},
                timeout=DEFAULT_TIMEOUT,
                verify=False,          # no queremos fallar por certificados raros
                allow_redirects=True,
            )
        except requests.RequestException:
            # Si HEAD falla, intentamos un GET ligero
            try:
                resp = requests.get(
                    url,
                    headers={"User-Agent": DEFAULT_USER_AGENT},
                    timeout=DEFAULT_TIMEOUT,
                    verify=False,
                    allow_redirects=True,
                    stream=True,
                )
            except requests.RequestException:
                continue

        server_header = resp.headers.get("Server", "")
        product, version = _parse_server_header(server_header)

        # Solo sobreescribimos si no había nada
        if product and not p.product:
            p.product = product
        if version and not p.version:
            p.version = version

