"""
Módulo 5 — Varredura de Vulnerabilidades (Multi-Stack)
Checks GENÉRICOS (sempre executados, independem da tecnologia) +
checks ESPECÍFICOS (condicionados à tecnologia detectada no módulo 3).
"""

import subprocess
import re
from modules.logger import log, warn


def _run_nikto(domain: str) -> str:
    log("Executando Nikto (pode demorar 2–5 minutos)...")
    try:
        r = subprocess.run([
            "nikto", "-h", f"https://{domain}", "-nointeractive",
            "-maxtime", "240", "-Tuning", "1234567890", "-Format", "txt"
        ], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=260)
        return r.stdout + r.stderr
    except FileNotFoundError:
        warn("Nikto não encontrado — pulando varredura Nikto")
        return ""
    except subprocess.TimeoutExpired:
        warn("Nikto excedeu timeout")
        return ""
    except Exception as e:
        warn(f"Erro Nikto: {e}")
        return ""


def _check_etag(domain: str) -> dict:
    """GENÉRICO — vazamento de inode via ETag (CVE-2003-1418)."""
    try:
        r = subprocess.run(
            ["curl", "-sI", "--max-time", "10", f"https://{domain}/robots.txt"],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=15
        )
        etag = re.search(r'[Ee][Tt]ag:\s*"?([^"\s]+)"?', r.stdout)
        if etag:
            val = etag.group(1)
            inode_leak = bool(re.match(r'^[a-f0-9]+-[a-f0-9]+-[a-f0-9]+$', val))
            return {"present": True, "value": val, "inode_leak": inode_leak}
        return {"present": False, "value": None, "inode_leak": False}
    except Exception:
        return {"present": False, "value": None, "inode_leak": False}


def _check_ssl(domain: str) -> dict:
    """GENÉRICO — informações do certificado SSL."""
    try:
        r = subprocess.run([
            "curl", "-sv", "--max-time", "10", f"https://{domain}", "-o", "/dev/null"
        ], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=15)
        output = r.stderr

        issuer   = re.search(r'issuer:\s*(.+)', output)
        subject  = re.search(r'subject:\s*(.+)', output)
        ssl_ver  = re.search(r'SSL connection using\s+(\S+)\s*/\s*(\S+)', output)
        domain_root = domain.split('.', 1)[-1] if '.' in domain else domain
        wildcard = re.search(r'\*\.' + re.escape(domain_root), output)

        return {
            "issuer":       issuer.group(1).strip()  if issuer  else "N/A",
            "subject":      subject.group(1).strip()  if subject else "N/A",
            "tls_version":  ssl_ver.group(1)           if ssl_ver else "N/A",
            "cipher":       ssl_ver.group(2)           if ssl_ver else "N/A",
            "wildcard_cert": bool(wildcard),
        }
    except Exception as e:
        warn(f"Erro SSL check: {e}")
        return {}


def _check_xmlrpc(domain: str) -> dict:
    """ESPECÍFICO WordPress — mantido por compatibilidade, condicionado pelo chamador."""
    try:
        r = subprocess.run(
            ["curl", "-sI", "--max-time", "10", f"https://{domain}/xmlrpc.php"],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=15
        )
        codes = [int(m) for m in re.findall(r"HTTP/\S+\s+(\d+)", r.stdout)]
        code = codes[-1] if codes else 0
        return {"status_code": code, "exists": code != 404, "blocked": code == 403, "accessible": code == 200}
    except Exception:
        return {"status_code": -1, "exists": False, "blocked": False, "accessible": False}


def _check_login_rate_limit(domain: str, login_path: str) -> dict:
    """GENÉRICO — adapta o path de login conforme a tecnologia (parametrizado)."""
    try:
        statuses = []
        for _ in range(3):
            r = subprocess.run(
                ["curl", "-sI", "--max-time", "8", f"https://{domain}{login_path}"],
                capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=10
            )
            codes = [int(m) for m in re.findall(r"HTTP/\S+\s+(\d+)", r.stdout)]
            statuses.append(codes[-1] if codes else 0)
        all_200 = all(s == 200 for s in statuses)
        return {"statuses": statuses, "rate_limit_found": not all_200, "accessible_200": all_200}
    except Exception:
        return {"statuses": [], "rate_limit_found": False, "accessible_200": False}


def _check_csrf_in_form(domain: str, form_path: str) -> dict:
    """GENÉRICO — verifica presença de qualquer token CSRF comum no HTML do formulário."""
    try:
        r = subprocess.run(
            ["curl", "-sL", "--max-time", "10", f"https://{domain}{form_path}"],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=15
        )
        html = r.stdout
        csrf_patterns = [
            r"_wpnonce", r"wp_nonce", r"csrf[_-]?token", r"csrfmiddlewaretoken",
            r"authenticity_token", r"__RequestVerificationToken", r"_token"
        ]
        has_token = any(re.search(p, html, re.I) for p in csrf_patterns)
        return {"has_nonce": has_token, "missing_csrf": not has_token}
    except Exception:
        return {"has_nonce": False, "missing_csrf": True}


def _scan_uploads_for_sensitive(domain: str, upload_paths: list) -> list:
    """GENÉRICO — busca arquivos sensíveis em diretórios de upload comuns."""
    sensitive = []
    sensitive_extensions = [".pdf", ".xls", ".xlsx", ".doc", ".docx", ".csv", ".sql"]

    try:
        for path in upload_paths:
            r = subprocess.run(
                ["curl", "-sL", "--max-time", "10", f"https://{domain}{path}"],
                capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=15
            )
            for ext in sensitive_extensions:
                files = re.findall(rf'href=["\']([^"\']*{re.escape(ext)})["\']', r.stdout, re.I)
                for f in files:
                    full_url = f if f.startswith("http") else f"https://{domain}{f}"
                    sensitive.append({"url": full_url, "extension": ext, "path": path})
    except Exception:
        pass

    return sensitive


def run_vuln_scan(domain: str, tech_data: dict = None, skip_nikto: bool = False) -> dict:
    """
    tech_data: resultado do tech_finger.py — usado para adaptar checks
    de login/CSRF ao path correto da tecnologia detectada.
    """
    tech_data = tech_data or {}
    primary_id = tech_data.get("primary_tech_id", "unknown")
    result = {}

    # ── Nikto (GENÉRICO) ──────────────────────────────────────────────────────
    if not skip_nikto:
        result["nikto_raw"] = _run_nikto(domain)
        findings = []
        for line in result["nikto_raw"].splitlines():
            if line.startswith("+ ") and not line.startswith("+ Target") and not line.startswith("+ Start"):
                findings.append(line[2:].strip())
        result["nikto_findings"] = findings
        log(f"Nikto: {len(findings)} achados")
    else:
        warn("Nikto pulado (--skip-nikto)")
        result["nikto_raw"] = ""
        result["nikto_findings"] = []

    # ── ETag / inode (GENÉRICO) ───────────────────────────────────────────────
    log("Verificando ETag (CVE-2003-1418)...")
    result["etag"] = _check_etag(domain)
    if result["etag"]["inode_leak"]:
        warn(f"ETag vaza inode: {result['etag']['value']}")

    # ── SSL/TLS (GENÉRICO) ────────────────────────────────────────────────────
    log("Verificando SSL/TLS...")
    result["ssl"] = _check_ssl(domain)
    log(f"Certificado: {result['ssl'].get('issuer','N/A')}")
    log(f"TLS: {result['ssl'].get('tls_version','N/A')} / {result['ssl'].get('cipher','N/A')}")

    # ── Login path por tecnologia ─────────────────────────────────────────────
    login_paths_by_tech = {
        "wordpress": "/wp-login.php", "joomla": "/administrator/",
        "drupal": "/user/login", "django": "/admin/", "magento": "/admin/",
        "prestashop": "/admin/",
    }
    login_path = login_paths_by_tech.get(primary_id, "/login/")

    # ── xmlrpc.php (ESPECÍFICO WordPress) ─────────────────────────────────────
    if primary_id == "wordpress":
        log("Verificando xmlrpc.php...")
        result["xmlrpc"] = _check_xmlrpc(domain)
        log(f"xmlrpc.php: status {result['xmlrpc']['status_code']}")
    else:
        result["xmlrpc"] = {"status_code": 404, "exists": False, "blocked": False, "accessible": False}

    # ── Rate limiting no login (GENÉRICO, path adaptado) ──────────────────────
    log(f"Verificando rate limiting em {login_path}...")
    result["wplogin_rate"] = _check_login_rate_limit(domain, login_path)
    if result["wplogin_rate"]["accessible_200"]:
        warn(f"{login_path} sem rate limiting detectado")

    # ── CSRF no formulário de login (GENÉRICO, path adaptado) ─────────────────
    log(f"Verificando token CSRF em {login_path}...")
    result["csrf"] = _check_csrf_in_form(domain, login_path)
    if result["csrf"]["missing_csrf"]:
        warn("Formulário de login sem token CSRF aparente")

    # ── Uploads sensíveis (GENÉRICO, paths adaptados) ─────────────────────────
    upload_paths_by_tech = {
        "wordpress": ["/wp-content/uploads/2026/06/", "/wp-content/uploads/2025/", "/wp-content/uploads/"],
        "joomla":    ["/images/", "/media/"],
        "drupal":    ["/sites/default/files/"],
        "magento":   ["/media/"],
    }
    upload_paths = upload_paths_by_tech.get(primary_id, ["/uploads/", "/files/", "/media/"])
    log("Escaneando uploads em busca de arquivos sensíveis...")
    result["sensitive_uploads"] = _scan_uploads_for_sensitive(domain, upload_paths)
    if result["sensitive_uploads"]:
        warn(f"{len(result['sensitive_uploads'])} arquivo(s) sensível(is) encontrado(s) em uploads!")
        for f in result["sensitive_uploads"]:
            warn(f"  → {f['url']}")

    return result
