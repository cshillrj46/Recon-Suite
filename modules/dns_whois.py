"""
Módulo 1 — Reconhecimento Passivo: DNS, WHOIS, DNSSEC
Universal — independe da tecnologia da aplicação web.
"""

import subprocess
import re
from modules.logger import log, warn


def _run(cmd: list, timeout=20) -> str:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout)
        return r.stdout + r.stderr
    except Exception as e:
        warn(f"Erro ao executar {' '.join(cmd)}: {e}")
        return ""


def run_dns_whois(domain: str) -> dict:
    result = {}

    log("Executando whois...")
    whois_raw = _run(["whois", domain])
    result["whois_raw"] = whois_raw

    def extract(pattern, text, default="N/A"):
        m = re.search(pattern, text, re.IGNORECASE | re.MULTILINE)
        return m.group(1).strip() if m else default

    result["registrant"]  = extract(r"^owner:\s+(.+)$", whois_raw)
    result["country"]     = extract(r"^country:\s+(.+)$", whois_raw)
    result["created"]     = extract(r"^created:\s+(.+)$", whois_raw)
    result["expires"]     = extract(r"^expires:\s+(.+)$", whois_raw)
    result["status"]      = extract(r"^status:\s+(.+)$", whois_raw)

    log("Executando dig A...")
    a_raw = _run(["dig", domain, "A", "+short"])
    result["a_records"] = [l.strip() for l in a_raw.splitlines() if l.strip() and not l.startswith(";")]

    log("Executando dig NS...")
    ns_raw = _run(["dig", domain, "NS", "+short"])
    result["ns_records"] = [l.strip() for l in ns_raw.splitlines() if l.strip()]

    log("Executando dig MX...")
    mx_raw = _run(["dig", domain, "MX", "+short"])
    result["mx_records"] = [l.strip() for l in mx_raw.splitlines() if l.strip()]

    log("Executando dig TXT...")
    txt_raw = _run(["dig", domain, "TXT", "+short"])
    result["txt_records"] = [l.strip() for l in txt_raw.splitlines() if l.strip()]

    spf = next((t for t in result["txt_records"] if "v=spf1" in t), None)
    result["spf"] = spf
    result["spf_softfail"] = spf is not None and "~all" in spf
    result["spf_hardfail"] = spf is not None and "-all" in spf
    result["brevo_detected"] = any("brevo-code" in t for t in result["txt_records"])

    log("Verificando DNSSEC...")
    dnssec_raw = _run(["dig", domain, "+dnssec", "+multi"])
    result["dnssec_raw"]     = dnssec_raw
    result["dnssec_enabled"] = "ad" in dnssec_raw.lower() and "RRSIG" in dnssec_raw

    cloudflare_ns = any("cloudflare" in ns.lower() for ns in result["ns_records"])
    result["cloudflare_proxy"] = cloudflare_ns
    result["ip_hidden"]        = cloudflare_ns
    result["cdn"] = "Cloudflare" if cloudflare_ns else "Desconhecido"
    result["mail_provider"] = "Google Workspace" if any("google" in mx.lower() for mx in result["mx_records"]) else "Desconhecido"

    log(f"IPs encontrados: {', '.join(result['a_records']) or 'N/A'}")
    log(f"NS: {', '.join(result['ns_records']) or 'N/A'}")
    log(f"DNSSEC: {'ATIVO' if result['dnssec_enabled'] else 'INATIVO'}")
    log(f"CDN: {result['cdn']}")

    return result
