from rich.console import Console
from rich.table import Table

console = Console()

def info(msg: str): console.print(f"[bold cyan]INFO[/]: {msg}")
def warn(msg: str): console.print(f"[bold yellow]WARN[/]: {msg}")
def error(msg: str): console.print(f"[bold red]ERROR[/]: {msg}")

def table(title: str, columns: list[str], rows: list[list[str]]):
    t = Table(title=title)
    for c in columns: t.add_column(c)
    for r in rows: t.add_row(*[str(x) for x in r])
    console.print(t)

