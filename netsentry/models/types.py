from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import List, Optional, Dict, Any
from ipaddress import ip_address  # 👈 nuevo

from pydantic import BaseModel, Field


class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


# Mapeo para cálculo de riesgos
SEVERITY_WEIGHTS: Dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
}


class PortInfo(BaseModel):
    port: int
    protocol: str = "tcp"
    service: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None


class Finding(BaseModel):
    id: str
    title: str
    severity: Severity
    details: str
    recommendation: str
    port: Optional[int] = None


class HostResult(BaseModel):
    ip: str
    hostname: Optional[str] = None
    ports: List[PortInfo] = Field(default_factory=list)
    findings: List[Finding] = Field(default_factory=list)

    def risk_score(self) -> int:
        """
        Calcula un score de riesgo sencillo sumando pesos por severidad.
        HIGH=3, MEDIUM=2, LOW=1, INFO=0
        """
        score = 0
        for f in self.findings:
            score += SEVERITY_WEIGHTS.get(f.severity, 0)
        return score

    def risk_level(self) -> str:
        """
        Devuelve un nivel de riesgo global para el host en base al hallazgo
        de mayor severidad.
        """
        if not self.findings:
            return "NONE"

        severities = {f.severity for f in self.findings}
        if Severity.HIGH in severities:
            return "HIGH"
        if Severity.MEDIUM in severities:
            return "MEDIUM"
        if Severity.LOW in severities:
            return "LOW"
        return "INFO"

    def device_type(self) -> str:
        """
        Intenta inferir de forma aproximada el tipo de dispositivo
        a partir de los puertos y servicios expuestos.

        No es fingerprinting avanzado; solo heurísticas sencillas
        para uso doméstico / académico.
        """
        if not self.ports:
            return "Dispositivo genérico / desconocido"

        ports = {p.port for p in self.ports}
        services = {(p.service or "").lower() for p in self.ports}

        has_http = any(
            p.port in (80, 8080, 443)
            or (p.service or "").lower().startswith("http")
            for p in self.ports
        )

        # ¿Tiene pinta de IP de gateway casera? (192.168.x.1 / .254, 10.x.x.1, etc.)
        gateway_like = False
        try:
            ip_obj = ip_address(self.ip)
            last_octet = self.ip.split(".")[-1]
            gateway_like = ip_obj.is_private and last_octet in {"1", "254"}
        except ValueError:
            gateway_like = False

        # 1) Routers / CPE típicos
        if (
            has_http
            and (
                53 in ports          # DNS
                or 23 in ports       # Telnet típico de router viejuno
                or 7547 in ports     # CWMP / TR-069
                or 1900 in ports     # UPnP SSDP
                or gateway_like      # 👈 nueva heurística para 192.168.x.1, etc.
            )
        ):
            return "Router / CPE"

        # 2) Impresoras de red
        if (
            515 in ports            # LPD
            or 9100 in ports        # HP JetDirect / RAW printing
            or "printer" in " ".join(services)
        ):
            return "Impresora de red"

        # 3) NAS / almacenamiento en red
        if (
            2049 in ports           # NFS
            or 445 in ports         # SMB
            or 139 in ports
            or "nas" in " ".join(services)
            or "smb" in services
        ):
            return "NAS / almacenamiento"

        # 4) Cámaras IP / vídeo
        if (
            554 in ports            # RTSP
            or 8554 in ports
            or "rtsp" in services
        ):
            return "Cámara IP / vídeo"

        # 5) Dispositivo Linux / IoT genérico (SSH + HTTP, pero sin RDP)
        if 22 in ports and has_http and 3389 not in ports:
            return "Dispositivo Linux / IoT"

        # 6) PC / servidor Windows (RDP o stack típico Windows)
        if 3389 in ports or {135, 139, 445} & ports:
            return "PC / servidor Windows"

        # 7) Desconocido
        return "Dispositivo genérico / desconocido"


class ScanResult(BaseModel):
    scan_id: str
    network: Optional[str]
    hosts: List[HostResult]
    started_at: datetime
    finished_at: datetime
    metadata: Dict[str, Any] = Field(default_factory=dict)

