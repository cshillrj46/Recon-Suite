#!/usr/bin/env python3
"""
Recon Suite — Automação de Pentest Multi-Tecnologia
Uso: python3 recon_suite.py <dominio> [--team "Nome da Equipe"] [--members "Nome1,Nome2"]

Detecta automaticamente a tecnologia do alvo (WordPress, Joomla, Drupal,
Laravel, Django, Next.js, API REST, etc.) e adapta os checks de endpoints
e as regras de classificação de vulnerabilidades de acordo com a stack
identificada, mantendo também checks genéricos universais.
"""

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from modules.dns_whois     import run_dns_whois
from modules.http_headers  import run_http_headers
from modules.tech_finger   import run_tech_fingerprint
from modules.endpoint_enum import run_endpoint_enum
from modules.vuln_scan     import run_vuln_scan
from modules.ai_analysis   import run_ai_analysis
from modules.report_gen    import generate_report
from modules.dashboard     import generate_dashboard
from modules.logger        import log, banner, step, ok, warn


def parse_args():
    p = argparse.ArgumentParser(description="Recon Suite — Automação de Pentest Multi-Tecnologia")
    p.add_argument("domain", help="Domínio alvo (ex: exemplo.com.br)")
    p.add_argument("--team", default="", help="Nome da equipe (opcional)")
    p.add_argument("--members", default="", help="Integrantes separados por vírgula (opcional)")
    p.add_argument("--advisor", default="", help="Orientador/responsável (opcional)")
    p.add_argument("--institution", default="", help="Instituição/empresa (opcional — se omitido, relatório não exibe cabeçalho institucional)")
    p.add_argument("--course", default="", help="Curso/departamento (opcional)")
    p.add_argument("--skip-gobuster", action="store_true", help="Pular Gobuster (mais lento)")
    p.add_argument("--skip-nikto", action="store_true", help="Pular Nikto (mais lento)")
    p.add_argument("--skip-ai", action="store_true", help="Pular IA — vai direto para motor de regras")
    p.add_argument("--ai-provider", default="auto", choices=["auto","claude","gemini","rules"],
                   help="Provedor de IA: auto (Claude->Gemini->regras), claude, gemini, ou rules (sem IA)")
    p.add_argument("--output-dir", default="output", help="Diretório de saída")
    return p.parse_args()


def main():
    args = parse_args()
    banner()

    domain    = args.domain.strip().lower().replace("https://","").replace("http://","").rstrip("/")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir   = Path(args.output_dir)
    res_dir   = Path("results")
    out_dir.mkdir(exist_ok=True)
    res_dir.mkdir(exist_ok=True)

    members = [m.strip() for m in args.members.split(",") if m.strip()] if args.members else []

    log(f"Alvo: {domain}")
    log(f"Equipe: {args.team}")
    log(f"Início: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}")
    print()

    results = {
        "domain": domain, "timestamp": timestamp,
        "team": args.team or "[NOME DA EQUIPE]",
        "members": members,
        "advisor": args.advisor or "[Responsável Técnico]",
        "institution": args.institution,
        "course": args.course,
        "date": datetime.now().strftime("%d/%m/%Y"),
    }

    # ── MÓDULO 1: DNS / WHOIS ────────────────────────────────────────────────
    step(1, "Reconhecimento Passivo — DNS, WHOIS, DNSSEC")
    results["dns"] = run_dns_whois(domain)
    ok("DNS/WHOIS concluído")

    # ── MÓDULO 2: Cabeçalhos HTTP ─────────────────────────────────────────────
    step(2, "Análise de Cabeçalhos HTTP")
    results["headers"] = run_http_headers(domain)
    ok("Cabeçalhos HTTP analisados")

    # ── MÓDULO 3: Fingerprinting (detecção automática de tecnologia) ────────
    step(3, "Fingerprinting de Tecnologias — Detecção Automática de Stack")
    results["tech"] = run_tech_fingerprint(domain)
    ok(f"Tecnologia identificada: {results['tech'].get('primary_tech_name','Desconhecida')}")

    # ── MÓDULO 4: Endpoints (adaptado à stack detectada) ────────────────────
    step(4, "Enumeração de Endpoints — Adaptada à Stack Detectada")
    results["endpoints"] = run_endpoint_enum(domain, tech_data=results["tech"], skip_gobuster=args.skip_gobuster)
    ok("Endpoints mapeados")

    # ── MÓDULO 5: Varredura de Vulnerabilidades (adaptada à stack) ──────────
    step(5, "Varredura de Vulnerabilidades — Genérica + Específica da Stack")
    results["vulnscan"] = run_vuln_scan(domain, tech_data=results["tech"], skip_nikto=args.skip_nikto)
    ok("Varredura concluída")

    # ── MÓDULO 6: Classificação de Vulnerabilidades (IA com fallback) ───────
    step(6, "Classificação de Vulnerabilidades")
    provider = "rules" if args.skip_ai else args.ai_provider
    results["vulnerabilities"] = run_ai_analysis(results, prefer=provider)
    ok(f"{len(results['vulnerabilities'])} vulnerabilidades identificadas")

    # ── Salva JSON bruto ───────────────────────────────────────────────────────
    json_path = res_dir / f"{domain}_{timestamp}.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)
    ok(f"Dados brutos salvos: {json_path}")

    # ── MÓDULO 7: Relatório Word ABNT ─────────────────────────────────────────
    step(7, "Geração do Relatório Word (ABNT NBR 14724)")
    docx_path = out_dir / f"Relatorio_Pentest_{domain}_{timestamp}.docx"
    generate_report(results, docx_path)
    ok(f"Relatório Word gerado: {docx_path}")

    # ── MÓDULO 8: Dashboard HTML ──────────────────────────────────────────────
    step(8, "Geração do Dashboard HTML")
    html_path = out_dir / f"Dashboard_{domain}_{timestamp}.html"
    generate_dashboard(results, html_path)
    ok(f"Dashboard gerado: {html_path}")

    # ── Resumo final ───────────────────────────────────────────────────────────
    print()
    print("=" * 60)
    print("  CONCLUÍDO")
    print("=" * 60)
    vuls = results.get("vulnerabilities", [])
    altas  = sum(1 for v in vuls if v.get("severity","").upper() in ("ALTO","URGENTE"))
    medias = sum(1 for v in vuls if v.get("severity","").upper() == "MÉDIO")
    baixas = sum(1 for v in vuls if v.get("severity","").upper() == "BAIXO")
    infos  = sum(1 for v in vuls if v.get("severity","").upper() == "INFORMATIVO")
    print(f"  Tecnologia detectada: {results['tech'].get('primary_tech_name','Desconhecida')}")
    print(f"  Vulnerabilidades: {len(vuls)} total")
    print(f"    Alta: {altas} | Médio: {medias} | Baixo: {baixas} | Info: {infos}")
    print(f"  Relatório: {docx_path}")
    print(f"  Dashboard: {html_path}")
    print(f"  Dados:     {json_path}")
    print("=" * 60)


if __name__ == "__main__":
    main()
