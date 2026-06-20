"""
Módulo 2 — Análise de Cabeçalhos HTTP
Universal — independe da tecnologia da aplicação web.
"""

import subprocess
import re
from modules.logger import log, warn


def _run_curl(url: str) -> str:
    try:
        r = subprocess.run(
            ["curl", "-sI", "--max-time", "15", "--location", url],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=20
        )
        return r.stdout
    except Exception as e:
        warn(f"Erro curl: {e}")
        return ""


def _parse_headers(raw: str) -> dict:
    headers = {}
    for line in raw.splitlines():
        if ":" in line and not line.startswith("HTTP/"):
            key, _, val = line.partition(":")
            headers[key.strip().lower()] = val.strip()
    return headers


def run_http_headers(domain: str) -> dict:
    url = f"https://{domain}"
    log(f"curl -sI {url}")
    raw = _run_curl(url)

    headers = _parse_headers(raw)
    result  = {"raw": raw, "headers": headers, "findings": []}

    m = re.search(r"HTTP/(\S+)\s+(\d+)", raw)
    result["http_version"] = m.group(1) if m else "?"
    result["status_code"]  = m.group(2) if m else "?"

    result["hsts_present"]              = "strict-transport-security" in headers
    result["x_frame_options"]           = headers.get("x-frame-options", None)
    result["x_content_type_options"]    = headers.get("x-content-type-options", None)
    result["csp_enforcement"]           = "content-security-policy" in headers
    result["csp_report_only"]           = "content-security-policy-report-only" in headers
    result["referrer_policy"]           = headers.get("referrer-policy", None)
    result["permissions_policy"]        = headers.get("permissions-policy", None)
    result["x_powered_by"]              = headers.get("x-powered-by", None)
    result["server"]                    = headers.get("server", None)
    result["cf_ray"]                    = headers.get("cf-ray", None)
    result["cloudflare_detected"]       = "cf-ray" in headers or headers.get("server","").lower() == "cloudflare"

    csp_val = headers.get("content-security-policy", "") or headers.get("content-security-policy-report-only", "")
    result["csp_unsafe_inline"] = "unsafe-inline" in csp_val
    result["csp_unsafe_eval"]   = "unsafe-eval"   in csp_val
    result["csp_value"]         = csp_val

    hsts_val = headers.get("strict-transport-security","")
    result["hsts_value"]              = hsts_val
    result["hsts_include_subdomains"] = "includesubdomains" in hsts_val.lower()
    result["hsts_preload"]            = "preload" in hsts_val.lower()

    # CORS
    result["cors_acao"] = headers.get("access-control-allow-origin", None)
    result["cors_wildcard"] = result["cors_acao"] == "*"

    log("Verificando cookies (página principal)...")
    try:
        r2 = subprocess.run(
            ["curl", "-si", "--max-time", "15", f"https://{domain}/"],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=20
        )
        cookies_raw = r2.stdout
        result["cookies_raw"] = cookies_raw[:3000]
        result["any_cookie_no_httponly"] = "set-cookie" in cookies_raw.lower() and "httponly" not in cookies_raw.lower()
        result["any_cookie_no_samesite"] = "set-cookie" in cookies_raw.lower() and "samesite" not in cookies_raw.lower()
        # Mantido por compatibilidade com regras específicas de WordPress
        result["wp_test_cookie_found"]    = "wordpress_test_cookie" in cookies_raw.lower()
        result["wp_test_cookie_httponly"] = result["wp_test_cookie_found"] and "httponly" in cookies_raw.lower()
        result["wp_test_cookie_samesite"] = result["wp_test_cookie_found"] and "samesite" in cookies_raw.lower()
    except Exception as e:
        warn(f"Erro ao verificar cookies: {e}")
        result["wp_test_cookie_httponly"] = None
        result["wp_test_cookie_samesite"] = None
        result["wp_test_cookie_found"]    = None

    findings = []

    if not result["hsts_present"]:
        findings.append({"header": "HSTS", "status": "AUSENTE", "severity": "Alto"})
    else:
        findings.append({"header": "HSTS", "status": f"PRESENTE ({hsts_val[:60]})", "severity": "OK"})

    if result["x_frame_options"]:
        findings.append({"header": "X-Frame-Options", "status": f"PRESENTE ({result['x_frame_options']})", "severity": "OK"})
    else:
        findings.append({"header": "X-Frame-Options", "status": "AUSENTE", "severity": "Médio"})

    if not result["x_content_type_options"]:
        findings.append({"header": "X-Content-Type-Options", "status": "AUSENTE", "severity": "Médio"})
    else:
        findings.append({"header": "X-Content-Type-Options", "status": "PRESENTE", "severity": "OK"})

    if result["csp_report_only"] and not result["csp_enforcement"]:
        findings.append({"header": "CSP", "status": "Report-Only (não bloqueia)", "severity": "Médio"})
    elif result["csp_enforcement"]:
        sev = "Médio" if (result["csp_unsafe_inline"] or result["csp_unsafe_eval"]) else "OK"
        findings.append({"header": "CSP", "status": f"ENFORCEMENT {'(unsafe-inline/eval)' if sev=='Médio' else 'OK'}", "severity": sev})
    else:
        findings.append({"header": "CSP", "status": "AUSENTE", "severity": "Alto"})

    if not result["referrer_policy"]:
        findings.append({"header": "Referrer-Policy", "status": "AUSENTE", "severity": "Médio"})

    if not result["permissions_policy"]:
        findings.append({"header": "Permissions-Policy", "status": "AUSENTE", "severity": "Médio"})

    if result["x_powered_by"]:
        findings.append({"header": "X-Powered-By", "status": f"EXPOSTO ({result['x_powered_by']})", "severity": "Baixo"})

    if result["server"]:
        findings.append({"header": "Server", "status": f"EXPOSTO ({result['server']})", "severity": "Informativo"})

    if result["cors_wildcard"]:
        findings.append({"header": "CORS", "status": "Access-Control-Allow-Origin: * (irrestrito)", "severity": "Médio"})

    if result["wp_test_cookie_found"]:
        if not result["wp_test_cookie_httponly"]:
            findings.append({"header": "Cookie HttpOnly", "status": "wordpress_test_cookie sem HttpOnly", "severity": "Médio"})
        if not result["wp_test_cookie_samesite"]:
            findings.append({"header": "Cookie SameSite", "status": "wordpress_test_cookie sem SameSite", "severity": "Baixo"})
    elif result.get("any_cookie_no_httponly"):
        findings.append({"header": "Cookie HttpOnly", "status": "Cookie(s) sem flag HttpOnly", "severity": "Médio"})

    result["findings"] = findings

    for f in findings:
        icon = "✔" if f["severity"] == "OK" else ("⚠" if f["severity"] in ("Médio","Baixo","Informativo") else "✖")
        log(f"{icon} {f['header']}: {f['status']}")

    return result
