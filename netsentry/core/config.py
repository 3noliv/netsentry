from pathlib import Path
import yaml

DEFAULT_CONFIG = {
    "scan": {
        "timeout_ms": 500,
        "default_ports": [22, 80, 443]
    },
    "report": {
        "include_closed": False
    }
}

def save_default_config(path: str | Path):
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w", encoding="utf-8") as f:
        yaml.safe_dump(DEFAULT_CONFIG, f, sort_keys=False, allow_unicode=True)
    return str(p)

def load_config(path: str | Path | None):
    if not path:
        return DEFAULT_CONFIG
    p = Path(path)
    if not p.exists():
        return DEFAULT_CONFIG
    with p.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f) or DEFAULT_CONFIG

