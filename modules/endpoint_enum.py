"""
Módulo 4 — Enumeração de Endpoints e Estrutura (Multi-Stack)
Combina: endpoints genéricos (sempre testados) + endpoints específicos da
tecnologia detectada na Fase 3 (tech_finger.py) + arquivos sensíveis (genéricos
+ específicos) + Gobuster.
"""

import subprocess
import json
import re
import os
from modules.logger import log, warn
from modules.tech_catalog import get_tech_profile, GENERIC_SENSITIVE_FILES, GENERIC_ADMIN_PATHS


def _check_url(url: str) -> dict:
    try:
        r = subprocess.run(
            ["curl", "-sI", "--max-time", "10", "--location", url],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=15
        )
        codes = [int(m) for m in re.findall(r"HTTP/\S+\s+(\d+)", r.stdout)]
        final_code = codes[-1] if codes else 0
        redirect_to = None
        m = re.search(r"[Ll]ocation:\s*(.+)", r.stdout)
        if m: redirect_to = m.group(1).strip()
        return {"url": url, "status": final_code, "redirect": redirect_to}
    except Exception as e:
        return {"url": url, "status": -1, "error": str(e)}


def _run_gobuster(domain: str) -> str:
    log("Iniciando Gobuster (pode demorar alguns minutos)...")
    try:
        wordlists = [
            "/usr/share/dirb/wordlists/common.txt",
            "/usr/share/wordlists/dirb/common.txt",
            "/usr/share/dirb/wordlists/big.txt",
            "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
            "/usr/share/seclists/Discovery/Web-Content/common.txt",
        ]
        wordlist = next((w for w in wordlists if os.path.exists(w)), None)
        if not wordlist:
            warn("Wordlist não encontrada — pulando Gobuster")
            return ""

        r = subprocess.run([
            "gobuster", "dir", "-u", f"https://{domain}", "-w", wordlist,
            "-t", "20", "--timeout", "10s", "-q", "--no-error",
            "-o", "/tmp/gobuster_out.txt"
        ], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=180)
        return r.stdout + r.stderr
    except FileNotFoundError:
        warn("Gobuster não encontrado — pulando")
        return ""
    except subprocess.TimeoutExpired:
        warn("Gobuster excedeu timeout (3 min) — usando resultados parciais")
        try:
            with open("/tmp/gobuster_out.txt") as f:
                return f.read()
        except Exception:
            return ""
    except Exception as e:
        warn(f"Erro Gobuster: {e}")
        return ""


def _check_rest_api_users(domain: str) -> dict:
    """Checagem específica de WordPress — mantida por compatibilidade."""
    try:
        r = subprocess.run(
            ["curl", "-sL", "--max-time", "10", f"https://{domain}/wp-json/wp/v2/users"],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=15
        )
        try:
            users = json.loads(r.stdout)
            if isinstance(users, list) and len(users) > 0:
                return {"exposed": True, "count": len(users),
                        "usernames": [u.get("slug", u.get("name","?")) for u in users[:5]]}
        except Exception:
            pass
        return {"exposed": False, "count": 0, "usernames": []}
    except Exception:
        return {"exposed": False, "count": 0, "usernames": []}


def run_endpoint_enum(domain: str, tech_data: dict = None, skip_gobuster: bool = False) -> dict:
    """
    tech_data: resultado do módulo tech_finger.py (results["tech"]).
               Usado para carregar o perfil de endpoints da tecnologia detectada.
    """
    tech_data = tech_data or {}
    primary_id   = tech_data.get("primary_tech_id", "unknown")
    primary_name = tech_data.get("primary_tech_name", "Desconhecida")

    result = {
        "endpoints": [], "gobuster_raw": "", "rest_api_users": {},
        "tech_endpoints_tested": primary_id, "sensitive_files_found": [],
    }

    # ── Monta a lista de endpoints: genéricos + específicos da stack ────────
    endpoints_to_test = []

    # Admin paths genéricos (sempre testados)
    for path in GENERIC_ADMIN_PATHS:
        endpoints_to_test.append((path, f"Painel administrativo genérico"))

    # Endpoints específicos da tecnologia detectada
    profile = get_tech_profile(primary_id)
    if profile:
        endpoints_to_test.extend(profile.get("endpoints", []))
        log(f"Carregado perfil de endpoints para: {primary_name} ({len(profile.get('endpoints',[]))} endpoints específicos)")
    else:
        warn(f"Sem perfil de endpoints específico para '{primary_id}' — testando apenas checks genéricos")

    # Páginas comuns de conteúdo (genérico, baixo custo)
    endpoints_to_test += [
        ("/robots.txt", "Robots.txt"),
        ("/sitemap.xml", "Sitemap"),
        ("/sitemap_index.xml", "Sitemap Index"),
        ("/feed/", "RSS Feed"),
        ("/contato/", "Formulário de Contato (pt-BR)"),
        ("/contact/", "Formulário de Contato (en)"),
        ("/sobre/", "Sobre (pt-BR)"),
        ("/about/", "About (en)"),
    ]

    # Remove duplicatas mantendo ordem
    seen = set()
    unique_endpoints = []
    for path, label in endpoints_to_test:
        if path not in seen:
            seen.add(path)
            unique_endpoints.append((path, label))

    # ── Testa cada endpoint ───────────────────────────────────────────────────
    log(f"Testando {len(unique_endpoints)} endpoints ({primary_name} + genéricos)...")
    for path, label in unique_endpoints:
        url = f"https://{domain}{path}"
        check = _check_url(url)
        check["label"] = label
        check["path"]  = path
        result["endpoints"].append(check)

        st = check["status"]
        if st == 200:
            log(f"  200 OK  → {path} ({label})")
        elif st in (301, 302):
            redir = (check.get("redirect") or "")[:60]
            log(f"  {st} →   {path} ↷ {redir}")
        elif st == 403:
            log(f"  403     → {path} (bloqueado)")
        elif st == 500:
            warn(f"  500 ERR → {path} (arquivo existe!)")

    # ── Arquivos sensíveis: genéricos + específicos da stack ────────────────
    sensitive_paths = list(GENERIC_SENSITIVE_FILES)
    if profile:
        sensitive_paths += profile.get("sensitive_files", [])
    sensitive_paths = list(dict.fromkeys(sensitive_paths))  # dedup mantendo ordem

    log(f"Verificando {len(sensitive_paths)} arquivos sensíveis (genéricos + específicos)...")
    for path in sensitive_paths:
        url = f"https://{domain}{path}"
        check = _check_url(url)
        if check["status"] == 200:
            warn(f"  ARQUIVO SENSÍVEL ACESSÍVEL: {path}")
            result["sensitive_files_found"].append({"path": path, "url": url, "status": 200})

    # ── REST API users (específico WordPress, mantido por compatibilidade) ──
    if primary_id == "wordpress":
        log("Verificando enumeração de usuários via REST API...")
        result["rest_api_users"] = _check_rest_api_users(domain)
        if result["rest_api_users"]["exposed"]:
            warn(f"REST API expõe {result['rest_api_users']['count']} usuário(s): {result['rest_api_users']['usernames']}")
    else:
        result["rest_api_users"] = {"exposed": False, "count": 0, "usernames": []}

    # ── Diretório de uploads (genérico, vale para WP/Joomla/etc.) ────────────
    uploads_paths = ["/wp-content/uploads/", "/uploads/", "/media/", "/files/"]
    result["uploads_listable"] = False
    for up in uploads_paths:
        c = _check_url(f"https://{domain}{up}")
        if c["status"] == 200:
            result["uploads_listable"] = True
            result["uploads_path"] = up
            break

    # ── Gobuster ──────────────────────────────────────────────────────────────
    if not skip_gobuster:
        result["gobuster_raw"] = _run_gobuster(domain)
        gobuster_findings = []
        for line in result["gobuster_raw"].splitlines():
            m = re.search(r'(/\S+)\s+\(Status:\s*(\d+)\)', line)
            if m:
                path, code = m.group(1), int(m.group(2))
                if code in (200, 301, 302, 403, 500):
                    gobuster_findings.append({"path": path, "status": code})
        result["gobuster_findings"] = gobuster_findings
        log(f"Gobuster: {len(gobuster_findings)} resultados relevantes")
    else:
        warn("Gobuster pulado (--skip-gobuster)")
        result["gobuster_findings"] = []

    ok_200 = [e for e in result["endpoints"] if e["status"] == 200]
    ok_500 = [e for e in result["endpoints"] if e["status"] == 500]
    log(f"Endpoints com 200 OK: {len(ok_200)}")
    log(f"Endpoints com 500 ERR: {len(ok_500)}")
    log(f"Arquivos sensíveis acessíveis: {len(result['sensitive_files_found'])}")

    return result
