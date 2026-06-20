"""
Módulo 6 — Análise de Vulnerabilidades com Fallback em Cadeia (Multi-Stack)
Tenta, em ordem: Claude API -> Gemini API -> Motor de Regras Local.
O contexto enviado à IA já inclui a tecnologia detectada automaticamente,
permitindo que a IA também adapte a análise à stack real do alvo.
"""

import json
import os
import re
from modules.logger import log, warn, ok
from modules.rule_engine import run_rule_based_analysis


PROMPT_TEMPLATE = """Você é um especialista em segurança ofensiva e análise de vulnerabilidades.

Com base nos dados de reconhecimento e varredura abaixo, gere uma lista completa de vulnerabilidades identificadas no domínio analisado, no formato JSON.

DADOS COLETADOS:
{context}

INSTRUÇÕES:
1. A tecnologia/stack do alvo já foi identificada automaticamente (ver seção TECNOLOGIA DETECTADA) — adapte toda a análise a essa stack específica. NÃO assuma WordPress se outra tecnologia foi detectada.
2. Classifique cada vulnerabilidade com: id (VUL-001, VUL-002...), title, severity (Alto/Médio/Baixo/Informativo/Descartada), owasp (ex: A05 – Security Misconfiguration), certainty (Alta/Média/Baixa/Não confirmada), tool (ferramenta que identificou), impact (análise de impacto técnico e de negócio), remediation (sugestão de correção específica e acionável para a stack identificada)
3. Inclua TODAS as vulnerabilidades que os dados suportam, mesmo as informativas
4. Se um dado indica "descartado", inclua como VUL com severity=Descartada
5. Ordene por severidade: Alto → Médio → Baixo → Informativo → Descartada
6. Seja específico: mencione versões, endpoints e valores reais coletados nos dados

Responda APENAS com JSON válido, sem markdown, sem texto antes ou depois:
[
  {{
    "id": "VUL-001",
    "title": "título da vulnerabilidade",
    "severity": "Alto",
    "owasp": "A01 – Broken Access Control",
    "certainty": "Alta",
    "tool": "ferramenta",
    "impact": "descrição do impacto técnico e de negócio",
    "remediation": "sugestão de correção detalhada"
  }}
]"""


def _build_context(results: dict) -> str:
    """Monta resumo dos dados coletados para enviar à IA, incluindo a stack detectada."""
    domain = results.get("domain", "")
    dns    = results.get("dns", {})
    hdrs   = results.get("headers", {})
    tech   = results.get("tech", {})
    ep     = results.get("endpoints", {})
    vs     = results.get("vulnscan", {})

    lines = [f"Domínio analisado: {domain}", ""]

    lines += [
        "=== TECNOLOGIA DETECTADA ===",
        f"Tecnologia principal: {tech.get('primary_tech_name','Desconhecida')} (categoria: {tech.get('primary_tech_category','N/A')})",
        f"Versão (se identificada): {tech.get('tech_specific',{}).get('version','N/A')}",
        f"Outras tecnologias possíveis: {', '.join(m['name'] for m in tech.get('tech_matches',[])[1:4])}",
        "",
    ]

    lines += [
        "=== DNS / WHOIS ===",
        f"IPs: {', '.join(dns.get('a_records', []))}",
        f"NS: {', '.join(dns.get('ns_records', []))}",
        f"MX: {', '.join(dns.get('mx_records', []))}",
        f"TXT: {', '.join(dns.get('txt_records', []))}",
        f"DNSSEC ativo: {dns.get('dnssec_enabled', False)}",
        f"CDN: {dns.get('cdn', 'N/A')}",
        f"SPF softfail (~all): {dns.get('spf_softfail', False)}",
        "",
    ]

    lines += [
        "=== CABEÇALHOS HTTP ===",
        f"HSTS: {hdrs.get('hsts_present')} | valor: {hdrs.get('hsts_value','')}",
        f"X-Frame-Options: {hdrs.get('x_frame_options')}",
        f"X-Content-Type-Options: {hdrs.get('x_content_type_options')}",
        f"CSP enforcement: {hdrs.get('csp_enforcement')} | report-only: {hdrs.get('csp_report_only')}",
        f"CSP unsafe-inline: {hdrs.get('csp_unsafe_inline')} | unsafe-eval: {hdrs.get('csp_unsafe_eval')}",
        f"CORS wildcard: {hdrs.get('cors_wildcard')}",
        f"Referrer-Policy: {hdrs.get('referrer_policy')}",
        f"Permissions-Policy: {hdrs.get('permissions_policy')}",
        f"X-Powered-By: {hdrs.get('x_powered_by')}",
        f"Server: {hdrs.get('server')}",
        f"Cloudflare detectado: {hdrs.get('cloudflare_detected')}",
        "",
    ]

    lines += [
        "=== DETALHES DA STACK ===",
        f"jQuery: {tech.get('jquery_version','N/A')}",
        f"GTM: {tech.get('gtm_id','Não detectado')}",
        f"E-mails expostos: {tech.get('exposed_emails','Nenhum')}",
        f"Scripts externos: {', '.join(tech.get('external_scripts',[])[:5])}",
        "",
    ]

    ep_list = ep.get("endpoints", [])
    ep_200  = [e["path"] for e in ep_list if e.get("status") == 200]
    ep_500  = [e["path"] for e in ep_list if e.get("status") == 500]
    sensitive_files = ep.get("sensitive_files_found", [])
    lines += [
        "=== ENDPOINTS E ARQUIVOS ===",
        f"Retornam 200 OK: {', '.join(ep_200)}",
        f"Retornam 500: {', '.join(ep_500)}",
        f"Arquivos sensíveis genéricos acessíveis: {[s['path'] for s in sensitive_files]}",
        f"Uploads acessível: {ep.get('uploads_listable')}",
        "",
    ]

    sensitive_uploads = vs.get("sensitive_uploads", [])
    lines += [
        "=== VARREDURA DE VULNERABILIDADES ===",
        f"Rate limiting ausente no login: {vs.get('wplogin_rate',{}).get('accessible_200')}",
        f"CSRF ausente no formulário de login: {vs.get('csrf',{}).get('missing_csrf')}",
        f"ETag inode leak: {vs.get('etag',{}).get('inode_leak')}",
        f"SSL issuer: {vs.get('ssl',{}).get('issuer','N/A')}",
        f"SSL wildcard: {vs.get('ssl',{}).get('wildcard_cert')}",
        f"Arquivos sensíveis em uploads: {len(sensitive_uploads)} encontrado(s)",
    ]
    for s in sensitive_uploads:
        lines.append(f"  → {s['url']}")
    lines += [f"Nikto achados ({len(vs.get('nikto_findings',[]))} total):"]
    for nf in vs.get("nikto_findings", [])[:15]:
        lines.append(f"  + {nf}")

    return "\n".join(lines)


def _parse_json_response(response: str) -> list:
    if not response:
        return []
    clean = re.sub(r'^```(?:json)?\s*', '', response.strip(), flags=re.MULTILINE)
    clean = re.sub(r'\s*```$', '', clean.strip(), flags=re.MULTILINE)
    try:
        return json.loads(clean)
    except json.JSONDecodeError:
        m = re.search(r'\[[\s\S]+\]', response)
        if m:
            try:
                return json.loads(m.group(0))
            except Exception:
                return []
        return []


def _try_claude(prompt: str) -> list:
    try:
        import anthropic
    except ImportError:
        warn("[Claude] Biblioteca 'anthropic' não instalada — pulando este provedor")
        return []

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        warn("[Claude] ANTHROPIC_API_KEY não definida — pulando este provedor")
        return []

    try:
        client = anthropic.Anthropic(api_key=api_key)
        msg = client.messages.create(
            model="claude-sonnet-4-6", max_tokens=4000,
            messages=[{"role": "user", "content": prompt}]
        )
        vuls = _parse_json_response(msg.content[0].text)
        if vuls:
            ok(f"[Claude] {len(vuls)} vulnerabilidades geradas")
        return vuls
    except anthropic.APIStatusError as e:
        warn(f"[Claude] Erro [{e.status_code}]: {e.message}")
        return []
    except Exception as e:
        warn(f"[Claude] Erro inesperado: {type(e).__name__}: {e}")
        return []


def _try_gemini(prompt: str) -> list:
    try:
        import google.generativeai as genai
    except ImportError:
        warn("[Gemini] Biblioteca 'google-generativeai' não instalada — pulando este provedor")
        return []

    api_key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
    if not api_key:
        warn("[Gemini] GEMINI_API_KEY não definida — pulando este provedor")
        return []

    try:
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel("gemini-2.0-flash")
        response = model.generate_content(prompt)
        vuls = _parse_json_response(response.text)
        if vuls:
            ok(f"[Gemini] {len(vuls)} vulnerabilidades geradas")
        return vuls
    except Exception as e:
        warn(f"[Gemini] Erro: {type(e).__name__}: {e}")
        return []


def run_ai_analysis(results: dict, prefer: str = "auto") -> list:
    """
    prefer: "auto" (Claude -> Gemini -> regras), "claude", "gemini", "rules".
    """
    context = _build_context(results)
    prompt  = PROMPT_TEMPLATE.format(context=context)

    providers = {"claude": _try_claude, "gemini": _try_gemini}
    order = {
        "auto":   ["claude", "gemini"],
        "claude": ["claude"],
        "gemini": ["gemini"],
        "rules":  [],
    }.get(prefer, ["claude", "gemini"])

    for name in order:
        log(f"Tentando provedor de IA: {name}...")
        vuls = providers[name](prompt)
        if vuls:
            return vuls

    warn("Nenhum provedor de IA disponível ou todos falharam — usando motor de regras local")
    return run_rule_based_analysis(results)
