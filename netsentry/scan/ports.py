import socket
import time
from typing import Iterable, Tuple

def tcp_connect(host: str, port: int, timeout_ms: int = 500) -> Tuple[str, int, str, int]:
    """Devuelve (proto, port, state, latency_ms)"""
    start = time.perf_counter()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout_ms / 1000.0)
            res = s.connect_ex((host, port))
            latency = int((time.perf_counter() - start) * 1000)
            if res == 0:
                return ("tcp", port, "open", latency)
            # 111/10061 típicamente "refused" -> closed
            return ("tcp", port, "closed", latency)
    except socket.timeout:
        latency = int((time.perf_counter() - start) * 1000)
        return ("tcp", port, "filtered", latency)
    except Exception:
        latency = int((time.perf_counter() - start) * 1000)
        return ("tcp", port, "filtered", latency)

def scan_ports(host: str, ports: Iterable[int], timeout_ms: int = 500):
    results = []
    for p in ports:
        proto, port, state, latency = tcp_connect(host, p, timeout_ms)
        results.append({"proto": proto, "port": port, "state": state, "latency_ms": latency})
    return results

