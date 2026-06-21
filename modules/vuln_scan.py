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
    """
    ESPECÍFICO WordPress — mantido por compatibilidade, condicionado pelo chamador.

    xmlrpc.php real, quando acessado via GET sem payload XML-RPC válido,
    devolve uma mensagem de erro XML característica ("XML-RPC server
    accepts POST requests only."). Confiar apenas no status 200 corre o
    mesmo risco dos demais checks: um WAF servindo página de bloqueio com
    200 seria contado como "xmlrpc acessível" incorretamente.
    """
    try:
        r = subprocess.run(
            ["curl", "-s", "-D", "-", "--max-time", "10", f"https://{domain}/xmlrpc.php"],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=15
        )
        raw = r.stdout
        header_end = raw.find("\r\n\r\n")
        if header_end == -1:
            header_end = raw.find("\n\n")
        headers_part = raw[:header_end] if header_end != -1 else raw
        body_part    = raw[header_end:] if header_end != -1 else ""

        codes = [int(m) for m in re.findall(r"HTTP/\S+\s+(\d+)", headers_part)]
        code = codes[-1] if codes else 0

        waf_block = _looks_like_waf_block_page(body_part)
        looks_like_real_xmlrpc = "xml-rpc server accepts post" in body_part.lower() \
            or "<methodresponse>" in body_part.lower()

        accessible = (code == 200) and not waf_block

        return {
            "status_code": code, "exists": code != 404, "blocked": code == 403,
            "accessible": accessible,
            "waf_softblock": waf_block,
            "confirmed_real_xmlrpc": looks_like_real_xmlrpc,
        }
    except Exception:
        return {"status_code": -1, "exists": False, "blocked": False, "accessible": False,
                "waf_softblock": False, "confirmed_real_xmlrpc": False}


def _check_login_rate_limit(domain: str, login_path: str) -> dict:
    """
    GENÉRICO — testa rate limiting de forma realista.

    Importante: testar apenas GET/HEAD (curl -sI) é insuficiente e pode gerar
    falso positivo de "sem rate limiting" quando, na realidade, um WAF está
    bloqueando POSTs de login mas permitindo GETs normalmente (cenário comum
    em ambientes protegidos por Cloudflare/WAF). Este check faz POSTs reais
    simulando tentativas de login, e também envia um POST de controle com
    payload genérico (sem campos de login) para distinguir:
      - Bloqueio específico de login (WAF reconhece o payload de auth)
      - Bloqueio genérico de método POST (WAF bloqueia qualquer POST)
      - Ausência total de proteção (rate limiting realmente ausente)

    NUNCA envia uma senha que poderia ser válida — usa apenas valores
    claramente inválidos (timestamp + sufixo), preservando o caráter de
    teste de segurança e não de tentativa real de acesso não autorizado.
    """
    import time

    def _post(data: dict, path: str) -> dict:
        try:
            body = "&".join(f"{k}={v}" for k, v in data.items())
            r = subprocess.run([
                "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}|%{time_total}",
                "--max-time", "10", "-d", body, f"https://{domain}{path}"
            ], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=12)
            parts = r.stdout.strip().split("|")
            code = int(parts[0]) if parts[0].isdigit() else 0
            elapsed = float(parts[1]) if len(parts) > 1 else 0.0
            return {"status": code, "elapsed": elapsed}
        except Exception:
            return {"status": 0, "elapsed": 0.0}

    try:
        # 1) POSTs simulando tentativas de login (credenciais claramente inválidas)
        login_attempts = []
        for i in range(5):
            ts = int(time.time())
            res = _post({
                "log": "wpscan-rate-test",
                "pwd": f"invalid-test-{ts}-{i}",
                "wp-submit": "Log+In",
            }, login_path)
            login_attempts.append(res)
            time.sleep(0.5)

        login_statuses  = [a["status"]  for a in login_attempts]
        login_times     = [a["elapsed"] for a in login_attempts]

        # 2) POST de controle — payload genérico, sem campos de login,
        #    para verificar se o bloqueio é específico de auth ou geral
        control = _post({"teste": "valor_generico_controle"}, login_path)

        login_blocked_403   = all(s == 403 for s in login_statuses)
        control_blocked_403 = control["status"] == 403
        all_200             = all(s == 200 for s in login_statuses)

        # Classificação do cenário real
        if login_blocked_403 and control_blocked_403:
            scenario = "waf_blocks_all_post"
            rate_limit_found = True       # mitigado, mas não nativamente
            native_rate_limit = False     # WordPress em si não tem proteção própria
        elif login_blocked_403 and not control_blocked_403:
            scenario = "waf_blocks_login_specifically"
            rate_limit_found = True
            native_rate_limit = False
        elif all_200:
            scenario = "no_protection_detected"
            rate_limit_found = False
            native_rate_limit = False
        else:
            scenario = "inconclusive"
            rate_limit_found = not all_200
            native_rate_limit = False

        return {
            "login_statuses":     login_statuses,
            "login_times":        login_times,
            "control_status":     control["status"],
            "scenario":           scenario,
            "rate_limit_found":   rate_limit_found,
            "native_rate_limit":  native_rate_limit,
            "accessible_200":     all_200,
            # Compatibilidade com versões anteriores do código:
            "statuses":           login_statuses,
        }
    except Exception:
        return {
            "login_statuses": [], "login_times": [], "control_status": 0,
            "scenario": "error", "rate_limit_found": False,
            "native_rate_limit": False, "accessible_200": False, "statuses": [],
        }


def _check_csrf_in_form(domain: str, form_path: str) -> dict:
    """
    GENÉRICO — verifica presença de qualquer token CSRF comum no HTML do formulário.

    Cuidado: se a requisição for bloqueada por um WAF e a página de
    bloqueio for devolvida no lugar do formulário real, o HTML recebido
    nunca terá token CSRF — não porque o formulário não tenha proteção,
    mas porque não vimos o formulário de fato. Reportar "missing_csrf=True"
    nesse caso seria um falso positivo. Por isso verificamos primeiro se a
    página recebida parece ser o formulário esperado (presença de campos
    de login típicos) antes de concluir qualquer coisa sobre CSRF.
    """
    try:
        r = subprocess.run(
            ["curl", "-sL", "--max-time", "10", f"https://{domain}{form_path}"],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=15
        )
        html = r.stdout

        if _looks_like_waf_block_page(html):
            return {"has_nonce": False, "missing_csrf": False, "inconclusive": True,
                    "reason": "Página recebida parece ser bloqueio de WAF, não o formulário real"}

        # Confirma que de fato chegamos a algo parecido com um formulário
        # (tag <form> presente) antes de avaliar CSRF
        if "<form" not in html.lower():
            return {"has_nonce": False, "missing_csrf": False, "inconclusive": True,
                    "reason": "Nenhuma tag <form> encontrada na página — não foi possível validar CSRF"}

        csrf_patterns = [
            r"_wpnonce", r"wp_nonce", r"csrf[_-]?token", r"csrfmiddlewaretoken",
            r"authenticity_token", r"__RequestVerificationToken", r"_token"
        ]
        has_token = any(re.search(p, html, re.I) for p in csrf_patterns)
        return {"has_nonce": has_token, "missing_csrf": not has_token, "inconclusive": False}
    except Exception:
        return {"has_nonce": False, "missing_csrf": False, "inconclusive": True,
                "reason": "Erro ao buscar a página"}


def _looks_like_waf_block_page(html: str) -> bool:
    if not html:
        return False
    low = html.lower()
    signatures = [
        "just a moment", "checking your browser", "attention required! | cloudflare",
        "cf-error-details", "you have been blocked", "request blocked",
        "incapsula incident id", "the requested url was rejected", "akamaighost",
        "sucuri website firewall", "ddos protection by",
    ]
    return any(sig in low for sig in signatures)


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

    # ── Rate limiting no login (GENÉRICO, path adaptado, POST real) ──────────
    log(f"Verificando rate limiting em {login_path} (POST real com 5 tentativas + controle)...")
    result["wplogin_rate"] = _check_login_rate_limit(domain, login_path)
    rl = result["wplogin_rate"]
    scenario = rl.get("scenario", "")
    if scenario == "no_protection_detected":
        warn(f"{login_path} sem rate limiting detectado — POSTs de login aceitos sem bloqueio")
    elif scenario == "waf_blocks_all_post":
        warn(f"{login_path}: POST bloqueado por WAF (403) de forma genérica — sem rate limiting nativo do WordPress, risco residual se o WAF for removido/contornado")
    elif scenario == "waf_blocks_login_specifically":
        log(f"{login_path}: WAF bloqueia especificamente tentativas de login (403) — sem rate limiting nativo do WordPress")
    elif scenario == "inconclusive":
        warn(f"{login_path}: resultado inconclusivo, verificar manualmente")

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
