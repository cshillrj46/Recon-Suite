"""Logger com cores ANSI para terminal."""
import sys

RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
BLUE   = "\033[94m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

def banner():
    print(f"""
{BOLD}{BLUE}╔══════════════════════════════════════════════════════════╗
║     RECON SUITE — Automação de Pentest Multi-Tecnologia  ║
║     Reconhecimento, Varredura e Classificação de VULs    ║
╚══════════════════════════════════════════════════════════╝{RESET}
""")

def log(msg):   print(f"  {CYAN}»{RESET} {msg}")
def ok(msg):    print(f"  {GREEN}✔{RESET} {msg}")
def warn(msg):  print(f"  {YELLOW}⚠{RESET} {msg}")
def fail(msg):  print(f"  {RED}✖{RESET} {msg}", file=sys.stderr)
def step(n, msg): print(f"\n{BOLD}[{n}] {msg}{RESET}")
