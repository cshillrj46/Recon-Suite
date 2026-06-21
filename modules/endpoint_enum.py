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


def _check_url(url: str, fetch_body: bool = False) -> dict:
    """
    Verifica uma URL e retorna status, redirect e (opcionalmente) uma
    assinatura do corpo da resposta.

    fetch_body=True é necessário sempre que o resultado (200 vs não-200)
    for usado para concluir algo sensível (arquivo sensível exposto,
    diretório listável, endpoint real existente) — porque WAFs/CDNs
    frequentemente devolvem HTTP 200 com uma página de bloqueio, challenge
    JS ("Just a moment..."), ou página de erro customizada, em vez do
    404/403 esperado. Confiar apenas no status code nesses casos gera
    falsos positivos.
    """
    try:
        if fetch_body:
            r = subprocess.run(
                ["curl", "-s", "-D", "-", "--max-time", "10", "--location", url],
                capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=15
            )
            raw = r.stdout
            header_end = raw.find("\r\n\r\n")
            if header_end == -1:
                header_end = raw.find("\n\n")
            headers_part = raw[:header_end] if header_end != -1 else raw
            body_part    = raw[header_end:] if header_end != -1 else ""
        else:
            r = subprocess.run(
                ["curl", "-sI", "--max-time", "10", "--location", url],
                capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=15
            )
            headers_part = r.stdout
            body_part = ""

        codes = [int(m) for m in re.findall(r"HTTP/\S+\s+(\d+)", headers_part)]
        final_code = codes[-1] if codes else 0
        redirect_to = None
        m = re.search(r"[Ll]ocation:\s*(.+)", headers_part)
        if m: redirect_to = m.group(1).strip()

        content_length = None
        m_len = re.search(r"[Cc]ontent-[Ll]ength:\s*(\d+)", headers_part)
        if m_len: content_length = int(m_len.group(1))

        result = {"url": url, "status": final_code, "redirect": redirect_to,
                  "content_length": content_length}

        if fetch_body:
            result["waf_softblock"]  = _looks_like_waf_block(body_part)
            result["body_snippet"]   = body_part[:300]

        return result
    except Exception as e:
        return {"url": url, "status": -1, "error": str(e)}


# Assinaturas textuais comuns de páginas de bloqueio/challenge servidas com
# HTTP 200 por WAFs/CDNs — usadas para não confundir "200 OK" com "conteúdo
# real acessível". Lista não exaustiva; cresce conforme novos WAFs aparecem
# nos alvos testados.
_WAF_BLOCK_SIGNATURES = [
    "just a moment",                    # Cloudflare challenge
    "checking your browser",            # Cloudflare / outros
    "attention required! | cloudflare",
    "cf-error-details",
    "access denied",
    "you have been blocked",
    "request blocked",
    "incapsula incident id",            # Imperva/Incapsula
    "the requested url was rejected",   # F5 BIG-IP ASM
    "akamaighost",                      # Akamai
    "sucuri website firewall",
    "ddos protection by",
    "errors.edgesuite.net",
]


def _looks_like_waf_block(body: str) -> bool:
    if not body:
        return False
    low = body.lower()
    return any(sig in low for sig in _WAF_BLOCK_SIGNATURES)


def _looks_like_directory_listing(body: str) -> bool:
    """
    Heurística para distinguir uma listagem de diretório real (Apache/Nginx
    autoindex) de uma página 200 genérica (ex: index.php customizado,
    redirect para home, página de bloqueio).
    """
    if not body:
        return False
    low = body.lower()
    signatures = [
        "index of /",                      # Apache mod_autoindex
        "<title>index of",
        "directory listing for",           # Nginx autoindex customizado
        "parent directory</a>",
    ]
    return any(sig in low for sig in signatures)


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
    # fetch_body=True: vários consumidores downstream (rule_engine.py) tratam
    # "status 200" como prova de exposição real (wp-cron acessível, diretório
    # wp-content/wp-includes navegável etc.). Sem checar o corpo, um WAF que
    # devolve 200 com página de bloqueio geraria VULs fantasmas.
    log(f"Testando {len(unique_endpoints)} endpoints ({primary_name} + genéricos)...")
    for path, label in unique_endpoints:
        url = f"https://{domain}{path}"
        check = _check_url(url, fetch_body=True)
        check["label"] = label
        check["path"]  = path

        # Reclassifica 200 "fantasma" (WAF soft-block) como bloqueado, para
        # que as regras de vulnerabilidade não tratem como acesso real
        if check["status"] == 200 and check.get("waf_softblock"):
            check["status_raw"] = 200
            check["status"] = 200  # mantém o status real reportado ao usuário
            check["waf_softblock_confirmed"] = True

        result["endpoints"].append(check)

        st = check["status"]
        if st == 200 and check.get("waf_softblock_confirmed"):
            log(f"  200 (WAF block) → {path} ({label}) — conteúdo é página de bloqueio, não o recurso real")
        elif st == 200:
            log(f"  200 OK  → {path} ({label})")
        elif st in (301, 302):
            redir = (check.get("redirect") or "")[:60]
            log(f"  {st} →   {path} ↷ {redir}")
        elif st == 403:
            log(f"  403     → {path} (bloqueado)")
        elif st == 500:
            warn(f"  500 ERR → {path} (arquivo existe!)")

    # ── Arquivos sensíveis: genéricos + específicos da stack ────────────────
    # fetch_body=True é obrigatório aqui: reportar exposição de credenciais
    # (.env, .git/config etc.) com base só no status 200 é o tipo de falso
    # positivo mais grave que a ferramenta pode cometer — um WAF devolvendo
    # 200 com página de bloqueio não é o arquivo sensível de fato exposto.
    sensitive_paths = list(GENERIC_SENSITIVE_FILES)
    if profile:
        sensitive_paths += profile.get("sensitive_files", [])
    sensitive_paths = list(dict.fromkeys(sensitive_paths))  # dedup mantendo ordem

    log(f"Verificando {len(sensitive_paths)} arquivos sensíveis (genéricos + específicos)...")
    for path in sensitive_paths:
        url = f"https://{domain}{path}"
        check = _check_url(url, fetch_body=True)
        if check["status"] != 200:
            continue
        if check.get("waf_softblock"):
            log(f"  {path}: 200 OK mas conteúdo é página de bloqueio do WAF — ignorado (não é exposição real)")
            continue
        # Content-Length muito pequeno (<20 bytes) costuma ser página vazia/redirect disfarçado
        if check.get("content_length") is not None and check["content_length"] < 20:
            log(f"  {path}: 200 OK mas Content-Length suspeito ({check['content_length']} bytes) — ignorado")
            continue
        warn(f"  ARQUIVO SENSÍVEL ACESSÍVEL: {path}")
        result["sensitive_files_found"].append({
            "path": path, "url": url, "status": 200,
            "content_length": check.get("content_length"),
            "body_snippet": check.get("body_snippet", ""),
        })

    # ── REST API users (específico WordPress, mantido por compatibilidade) ──
    if primary_id == "wordpress":
        log("Verificando enumeração de usuários via REST API...")
        result["rest_api_users"] = _check_rest_api_users(domain)
        if result["rest_api_users"]["exposed"]:
            warn(f"REST API expõe {result['rest_api_users']['count']} usuário(s): {result['rest_api_users']['usernames']}")
    else:
        result["rest_api_users"] = {"exposed": False, "count": 0, "usernames": []}

    # ── Diretório de uploads (genérico, vale para WP/Joomla/etc.) ────────────
    # Importante: 200 OK em /wp-content/uploads/ NÃO significa listagem de
    # diretório habilitada — WordPress frequentemente serve um index.php
    # vazio ou redireciona para a home com 200. Só reportamos "listable" se
    # o corpo da resposta tiver a assinatura real de um autoindex
    # (Apache "Index of /", Nginx equivalente etc.).
    uploads_paths = ["/wp-content/uploads/", "/uploads/", "/media/", "/files/"]
    result["uploads_listable"] = False
    for up in uploads_paths:
        c = _check_url(f"https://{domain}{up}", fetch_body=True)
        if c["status"] != 200:
            continue
        if c.get("waf_softblock"):
            continue
        if _looks_like_directory_listing(c.get("body_snippet", "")):
            result["uploads_listable"] = True
            result["uploads_path"] = up
            break
        else:
            log(f"  {up}: 200 OK mas sem assinatura de directory listing — diretório acessível porém não listável")
            result["uploads_accessible_not_listable"] = up

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
