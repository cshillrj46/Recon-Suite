"""
Módulo 3 — Fingerprinting de Tecnologias (Multi-Stack)
Detecta automaticamente CMS, framework, e-commerce ou API através do
catálogo de fingerprints, sem assumir WordPress como alvo fixo.
"""

import subprocess
import re
try:
    import requests
    REQUESTS_OK = True
except ImportError:
    REQUESTS_OK = False

from modules.logger import log, warn, ok
from modules.tech_catalog import identify_technology, get_tech_profile


def _run_whatweb(domain: str) -> str:
    try:
        r = subprocess.run(
            ["whatweb", f"https://{domain}", "--color=never", "-a", "3"],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30
        )
        return r.stdout + r.stderr
    except FileNotFoundError:
        warn("whatweb não encontrado — usando análise HTML direta")
        return ""
    except Exception as e:
        warn(f"Erro whatweb: {e}")
        return ""


def _fetch_html_and_headers(domain: str) -> tuple:
    """Retorna (html, headers_dict, cookies_str)."""
    if REQUESTS_OK:
        try:
            r = requests.get(f"https://{domain}", timeout=15,
                             headers={"User-Agent": "Mozilla/5.0 (compatible; SecurityAudit/1.0)"})
            headers = {k.lower(): v for k, v in r.headers.items()}
            cookies_str = "; ".join(f"{k}={v}" for k, v in r.cookies.items())
            set_cookie_raw = r.headers.get("Set-Cookie", "")
            return r.text, headers, cookies_str + " " + set_cookie_raw
        except Exception as e:
            warn(f"Erro ao buscar HTML via requests: {e}")

    try:
        r = subprocess.run(["curl", "-sL", "--max-time", "15", f"https://{domain}"],
                           capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=20)
        r2 = subprocess.run(["curl", "-sI", "--max-time", "10", f"https://{domain}"],
                            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=15)
        headers = {}
        for line in r2.stdout.splitlines():
            if ":" in line:
                k, _, v = line.partition(":")
                headers[k.strip().lower()] = v.strip()
        return r.stdout, headers, headers.get("set-cookie", "")
    except Exception:
        return "", {}, ""


def _extract_generic_info(html: str, domain: str) -> dict:
    """Extrai informações que não dependem de uma tecnologia específica."""
    info = {}
    if not html:
        return info

    m = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']', html, re.I)
    if m:
        info["meta_generator"] = m.group(1)

    jq = re.search(r'jquery[.-]([\d.]+)(?:\.min)?\.js', html, re.I)
    if jq: info["jquery_version"] = jq.group(1)

    gtm = re.search(r"GTM-([A-Z0-9]+)", html)
    if gtm: info["gtm_id"] = f"GTM-{gtm.group(1)}"

    ga = re.search(r"G-([A-Z0-9]+)", html)
    if ga: info["ga4_id"] = f"G-{ga.group(1)}"

    brevo = re.search(r'brevo|sendinblue', html, re.I)
    if brevo: info["brevo_detected"] = True
    wk = re.search(r'webKey["\s:=]+["\']?([a-f0-9]{64})', html)
    if wk: info["brevo_webkey"] = wk.group(1)

    emails = list(set(re.findall(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}', html)))
    emails = [e for e in emails if not any(x in e for x in ["example", "schema", "w3.org", "sentry", ".png", ".jpg"])]
    info["exposed_emails"] = emails[:10]

    og_locale = re.search(r'<meta[^>]+property=["\']og:locale["\'][^>]+content=["\']([^"\']+)', html, re.I)
    if og_locale: info["og_locale"] = og_locale.group(1)

    robots = re.search(r'<meta[^>]+name=["\']robots["\'][^>]+content=["\']([^"\']+)', html, re.I)
    if robots: info["robots_meta"] = robots.group(1)

    ext_scripts = list(set(re.findall(r'src=["\']https?://(?!' + re.escape(domain) + r')([^"\'?]+)', html)))
    info["external_scripts"] = [s for s in ext_scripts if any(x in s for x in
        ["google", "cloudflare", "brevo", "cdn", "gtm", "analytics", "gtag", "fbq", "hotjar", "clarity"])][:15]

    return info


def _extract_cms_specific(tech_id: str, html: str, whatweb_raw: str) -> dict:
    """Extrai detalhes específicos de versão para a tecnologia detectada."""
    info = {}
    if tech_id == "wordpress":
        wp_ver = re.search(r'WordPress[\s/\[]?([\d.]+)', html + whatweb_raw, re.I)
        el_ver = re.search(r'Elementor[\s/\[]?([\d.]+)', html + whatweb_raw, re.I)
        if wp_ver: info["version"] = wp_ver.group(1)
        if el_ver: info["builder_plugin"] = f"Elementor {el_ver.group(1)}"
        theme = re.search(r'/wp-content/themes/([a-z0-9\-]+)/', html)
        if theme: info["theme"] = theme.group(1)
        plugins = list(set(re.findall(r'/wp-content/plugins/([a-z0-9\-]+)/', html)))
        info["plugins"] = plugins[:20]

    elif tech_id == "joomla":
        ver = re.search(r'Joomla!\s*([\d.]+)', html + whatweb_raw, re.I)
        if ver: info["version"] = ver.group(1)

    elif tech_id == "drupal":
        ver = re.search(r'Drupal\s*([\d.]+)', html + whatweb_raw, re.I)
        if ver: info["version"] = ver.group(1)

    elif tech_id == "magento":
        ver = re.search(r'Magento[\s/]([\d.]+)', html + whatweb_raw, re.I)
        if ver: info["version"] = ver.group(1)

    return info


def run_tech_fingerprint(domain: str) -> dict:
    result = {}

    # ── WhatWeb (fallback de fingerprinting, opcional) ───────────────────────
    log("Executando WhatWeb...")
    whatweb_raw = _run_whatweb(domain)
    result["whatweb_raw"] = whatweb_raw

    # ── HTML + headers + cookies brutos ──────────────────────────────────────
    log("Buscando HTML e cabeçalhos para fingerprinting...")
    html, headers, cookies = _fetch_html_and_headers(domain)
    result["html_length"] = len(html)
    result["raw_headers"]  = headers
    result["raw_cookies"]  = cookies

    # ── Identificação de tecnologia via catálogo ─────────────────────────────
    log("Identificando stack tecnológica...")
    matches = identify_technology(html, headers, cookies)
    result["tech_matches"] = matches

    if matches:
        primary = matches[0]
        result["primary_tech_id"]       = primary["id"]
        result["primary_tech_name"]     = primary["name"]
        result["primary_tech_category"] = primary["category"]
        ok(f"Tecnologia principal detectada: {primary['name']} (categoria: {primary['category']}, confiança: {primary['score']})")
        if len(matches) > 1:
            others = ", ".join(f"{m['name']} ({m['score']})" for m in matches[1:4])
            log(f"Outras tecnologias detectadas: {others}")
    else:
        result["primary_tech_id"]       = "unknown"
        result["primary_tech_name"]     = "Não identificada"
        result["primary_tech_category"] = "unknown"
        warn("Nenhuma tecnologia conhecida foi identificada no catálogo — tratando como stack genérica")

    # ── Detalhes específicos da tecnologia principal ─────────────────────────
    specific = _extract_cms_specific(result["primary_tech_id"], html, whatweb_raw)
    result["tech_specific"] = specific
    if specific.get("version"):
        log(f"Versão detectada: {result['primary_tech_name']} {specific['version']}")

    # ── Informações genéricas (independem da tecnologia) ─────────────────────
    generic = _extract_generic_info(html, domain)
    result.update(generic)

    # ── Compatibilidade retroativa (campos usados pelos módulos antigos) ────
    result["wordpress_version"] = specific.get("version") if result["primary_tech_id"] == "wordpress" else None
    result["elementor_version"] = specific.get("builder_plugin","").replace("Elementor ", "") if specific.get("builder_plugin") else None
    result["wp_theme"]          = specific.get("theme")
    result["wp_plugins"]        = specific.get("plugins", [])

    # ── robots.txt e sitemap (genéricos, independem da stack) ────────────────
    log("Verificando robots.txt...")
    try:
        robots_r = subprocess.run(
            ["curl", "-sL", "--max-time", "10", f"https://{domain}/robots.txt"],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=15
        )
        result["robots_txt"] = robots_r.stdout[:2000]
        result["wplogin_in_robots"] = "wp-login.php" in robots_r.stdout or "/admin" in robots_r.stdout
    except Exception:
        result["robots_txt"] = ""
        result["wplogin_in_robots"] = False

    log("Verificando sitemap.xml...")
    try:
        sm_r = subprocess.run(
            ["curl", "-sI", "--max-time", "10", f"https://{domain}/sitemap.xml"],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=15
        )
        result["sitemap_accessible"] = "200" in sm_r.stdout or "301" in sm_r.stdout
    except Exception:
        result["sitemap_accessible"] = False

    log(f"jQuery: {result.get('jquery_version','N/A')}")
    log(f"GTM: {result.get('gtm_id','Não detectado')}")
    log(f"E-mails expostos: {result.get('exposed_emails','Nenhum')}")
    log(f"wp-login/admin no robots.txt: {'SIM' if result.get('wplogin_in_robots') else 'NÃO'}")

    return result
