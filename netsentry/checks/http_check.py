from __future__ import annotations

from typing import Dict, Iterable

import requests
import ssl

from netsentry.models.types import HostResult, Finding, Severity
from netsentry.rules.loader import Rule

DEFAULT_TIMEOUT = 3
DEFAULT_USER_AGENT = "sentry-CLI/0.1"


def _iter_http_ports(host: HostResult) -> Iterable[tuple[int, str]]:
    """
    Devuelve (puerto, esquema) para los puertos que parecen HTTP/HTTPS.
    """
    for p in host.ports:
        service = (p.service or "").lower()

        if p.port in (80, 8080) or service == "http":
            yield p.port, "http"
        elif p.port == 443 or service == "https":
            yield p.port, "https"


def _get_tls_info(resp: requests.Response):
    """
    Intenta extraer información TLS (versión y certificado) de una respuesta HTTPS.

    Devuelve (cert_dict | None, tls_version_str | None).
    Nunca lanza excepción: si no puede obtener algo, devuelve (None, None).
    """
    cert = None
    tls_version = None
    try:
        raw = resp.raw
        sock = getattr(getattr(raw, "_connection", None), "sock", None)
        if sock is not None and isinstance(sock, ssl.SSLSocket):
            try:
                cert = sock.getpeercert()
            except Exception:
                cert = None
            try:
                tls_version = sock.version()
            except Exception:
                tls_version = None
    except Exception:
        cert = None
        tls_version = None
    return cert, tls_version


def run_http_checks(host: HostResult, rules: Dict[str, Rule]) -> None:
    """
    Ejecuta comprobaciones HTTP/HTTPS sobre los puertos web detectados
    y añade hallazgos directamente a host.findings.
    """
    for port, scheme in _iter_http_ports(host):
        url = f"{scheme}://{host.ip}:{port}"

        try:
            resp = requests.get(
                url,
                headers={"User-Agent": DEFAULT_USER_AGENT},
                timeout=DEFAULT_TIMEOUT,
                verify=(scheme == "https"),
                allow_redirects=True,
            )
        except requests.exceptions.SSLError:
            # Reintentamos sin verificación para poder inspeccionar TLS/cert
            try:
                resp = requests.get(
                    url,
                    headers={"User-Agent": DEFAULT_USER_AGENT},
                    timeout=DEFAULT_TIMEOUT,
                    verify=False,
                    allow_redirects=True,
                )
            except requests.RequestException:
                continue
        except requests.RequestException:
            continue

        # Normalizamos cabeceras a minúsculas para varios checks
        headers_l = {k.lower(): v for k, v in resp.headers.items()}

        # ------------------------------------------------------------------
        # HTTP sin TLS → HTTP_NO_TLS
        # ------------------------------------------------------------------
        if scheme == "http" and "HTTP_NO_TLS" in rules:
            r = rules["HTTP_NO_TLS"]
            host.findings.append(
                Finding(
                    id="HTTP_NO_TLS",
                    title=r.title,
                    severity=Severity(r.severity),
                    details=f"Servicio HTTP sin TLS detectado en {host.ip}:{port}.",
                    recommendation=r.recommendation,
                    port=port,
                )
            )

        # ------------------------------------------------------------------
        # Información TLS (solo si HTTPS)
        # ------------------------------------------------------------------
        cert = None
        tls_version = None
        if scheme == "https":
            cert, tls_version = _get_tls_info(resp)

            # TLS antiguo / débil → TLS-OLD-VERSION
            if tls_version and "TLS-OLD-VERSION" in rules:
                # Valores típicos: 'TLSv1', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3'
                if tls_version in ("TLSv1", "TLSv1.1"):
                    r = rules["TLS-OLD-VERSION"]
                    host.findings.append(
                        Finding(
                            id="TLS-OLD-VERSION",
                            title=r.title,
                            severity=Severity(r.severity),
                            details=(
                                f"El servicio HTTPS en {host.ip}:{port} negocia "
                                f"{tls_version}, considerado obsoleto."
                            ),
                            recommendation=r.recommendation,
                            port=port,
                        )
                    )

            # Certificado autofirmado → CERT-SELF-SIGNED
            if cert and "CERT-SELF-SIGNED" in rules:
                issuer = cert.get("issuer")
                subject = cert.get("subject")
                # Heurística sencilla: issuer == subject ⇒ autofirmado
                if issuer and subject and issuer == subject:
                    r = rules["CERT-SELF-SIGNED"]
                    host.findings.append(
                        Finding(
                            id="CERT-SELF-SIGNED",
                            title=r.title,
                            severity=Severity(r.severity),
                            details=(
                                f"El certificado TLS presentado por {host.ip}:{port} "
                                f"parece autofirmado."
                            ),
                            recommendation=r.recommendation,
                            port=port,
                        )
                    )

        # ------------------------------------------------------------------
        # HTTPS sin HSTS → HTTP_NO_HSTS
        # ------------------------------------------------------------------
        if scheme == "https" and "HTTP_NO_HSTS" in rules:
            if "strict-transport-security" not in headers_l:
                r = rules["HTTP_NO_HSTS"]
                host.findings.append(
                    Finding(
                        id="HTTP_NO_HSTS",
                        title=r.title,
                        severity=Severity(r.severity),
                        details=f"Servicio HTTPS sin cabecera HSTS en {host.ip}:{port}.",
                        recommendation=r.recommendation,
                        port=port,
                    )
                )

        # ------------------------------------------------------------------
        # Cabeceras de seguridad faltantes → HTTP_MISSING_SEC_HEADERS
        # ------------------------------------------------------------------
        if "HTTP_MISSING_SEC_HEADERS" in rules:
            missing = []

            # Cabeceras clásicas de seguridad
            for h in ("content-security-policy", "x-frame-options", "x-content-type-options"):
                if h not in headers_l:
                    missing.append(h)

            # Si es HTTPS, también comprobamos HSTS aquí para el mensaje
            if scheme == "https" and "strict-transport-security" not in headers_l:
                missing.append("strict-transport-security (HSTS)")

            if missing:
                r = rules["HTTP_MISSING_SEC_HEADERS"]
                host.findings.append(
                    Finding(
                        id="HTTP_MISSING_SEC_HEADERS",
                        title=r.title,
                        severity=Severity(r.severity),
                        details=(
                            "La respuesta HTTP de "
                            f"{host.ip}:{port} no incluye cabeceras de seguridad "
                            f"recomendadas: {', '.join(missing)}."
                        ),
                            recommendation=r.recommendation,
                        port=port,
                    )
                )

        # ------------------------------------------------------------------
        # HTTP Basic Auth → HTTP_BASIC_AUTH
        # ------------------------------------------------------------------
        if "HTTP_BASIC_AUTH" in rules:
            wa = resp.headers.get("WWW-Authenticate", "")
            if "basic" in wa.lower():
                r = rules["HTTP_BASIC_AUTH"]
                host.findings.append(
                    Finding(
                        id="HTTP_BASIC_AUTH",
                        title=r.title,
                        severity=Severity(r.severity),
                        details=f"Uso de autenticación HTTP Basic en {host.ip}:{port}.",
                        recommendation=r.recommendation,
                        port=port,
                    )
                )

        # ------------------------------------------------------------------
        # Formularios de login servidos por HTTP → HTTP_LOGIN_OVER_HTTP
        # ------------------------------------------------------------------
        if "HTTP_LOGIN_OVER_HTTP" in rules and scheme == "http":
            body = ""
            try:
                body = resp.text[:4096]  # limitamos tamaño por si acaso
            except Exception:
                body = ""

            body_l = body.lower()
            if "<form" in body_l and "type=\"password\"" in body_l:
                r = rules["HTTP_LOGIN_OVER_HTTP"]
                host.findings.append(
                    Finding(
                        id="HTTP_LOGIN_OVER_HTTP",
                        title=r.title,
                        severity=Severity(r.severity),
                        details=(
                            "Formulario de login servido sin cifrar en "
                            f"{host.ip}:{port}."
                        ),
                        recommendation=r.recommendation,
                        port=port,
                    )
                )

        # ------------------------------------------------------------------
        # Listado de directorios → HTTP_DIR_LISTING
        # ------------------------------------------------------------------
        if "HTTP_DIR_LISTING" in rules:
            text = ""
            try:
                text = resp.text[:4096]
            except Exception:
                text = ""
            text_l = text.lower()
            if (
                "index of /" in text_l
                or "<title>index of" in text_l
                or "directory listing for" in text_l
            ):
                r = rules["HTTP_DIR_LISTING"]
                host.findings.append(
                    Finding(
                        id="HTTP_DIR_LISTING",
                        title=r.title,
                        severity=Severity(r.severity),
                        details=f"Posible listado de directorios en {host.ip}:{port}.",
                        recommendation=r.recommendation,
                        port=port,
                    )
                )

        # ------------------------------------------------------------------
        # Info genérica de servicio web → GENERIC-HTTP-INFO
        # ------------------------------------------------------------------
        if "GENERIC-HTTP-INFO" in rules:
            r = rules["GENERIC-HTTP-INFO"]
            host.findings.append(
                Finding(
                    id="GENERIC-HTTP-INFO",
                    title=r.title,
                    severity=Severity(r.severity),
                    details=f"Servicio web accesible en {host.ip}:{port}.",
                    recommendation=r.recommendation,
                    port=port,
                )
            )

