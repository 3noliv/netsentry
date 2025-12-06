from __future__ import annotations

import platform
import subprocess


def ping_host(ip: str, timeout_ms: int = 300) -> bool:
    """
    Devuelve True si el host responde a un único ping ICMP.
    Usa el comando 'ping' del sistema operativo.
    """
    system = platform.system().lower()

    if system == "windows":
        # -n 1 : un solo paquete
        # -w X : timeout en ms
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    else:
        # Linux/macOS:
        # -c 1 : un solo paquete
        # -W X : timeout en segundos (entero)
        timeout_s = max(1, int((timeout_ms + 999) // 1000))
        cmd = ["ping", "-c", "1", "-W", str(timeout_s), ip]

    result = subprocess.run(
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return result.returncode == 0

