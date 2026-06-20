"""
Motor de Regras — Classificação de Vulnerabilidades sem IA (Multi-Stack)
Codifica conhecimento em regras determinísticas, divididas em duas camadas:

  1. REGRAS GENÉRICAS  — aplicam a qualquer stack (headers, DNS, TLS, cookies,
     CORS, arquivos sensíveis genéricos, painéis admin expostos).
  2. REGRAS POR TECNOLOGIA — disparam apenas se a stack correspondente foi
     detectada (ex: regras de WordPress só avaliam se primary_tech_id ==
     "wordpress"). Isso evita falsos positivos como "xmlrpc.php" em um site
     Django.

Vantagens sobre IA: gratuito, instantâneo, determinístico e auditável.
"""

from modules.logger import log


def _vul(id_, title, severity, owasp, certainty, tool, impact, remediation):
    return {
        "id": id_, "title": title, "severity": severity, "owasp": owasp,
        "certainty": certainty, "tool": tool, "impact": impact, "remediation": remediation,
    }


# ═══════════════════════════════════════════════════════════════════════════
# CAMADA 1 — REGRAS GENÉRICAS (qualquer tecnologia)
# ═══════════════════════════════════════════════════════════════════════════
def _generic_rules(results: dict, next_id) -> list:
    dns  = results.get("dns", {})
    hdrs = results.get("headers", {})
    tech = results.get("tech", {})
    ep   = results.get("endpoints", {})
    vs   = results.get("vulnscan", {})

    vuls = []

    # ── Cabeçalhos de segurança ausentes ─────────────────────────────────────
    missing_headers = [f for f in hdrs.get("findings", []) if f.get("severity") in ("Médio", "Alto")
                        and f.get("header") in ("X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy")]
    if missing_headers:
        names = ", ".join(f["header"] for f in missing_headers)
        vuls.append(_vul(
            next_id(), "Cabeçalhos de segurança HTTP ausentes ou incompletos",
            "Médio", "A05 – Security Misconfiguration", "Alta", "curl -I",
            f"Ausência de {names}. X-Content-Type-Options ausente permite MIME sniffing; Referrer-Policy ausente pode vazar URLs internas; Permissions-Policy ausente deixa APIs do browser sem controle de acesso.",
            "Adicionar via .htaccess, nginx.conf ou middleware da aplicação: X-Content-Type-Options: nosniff, Referrer-Policy: strict-origin-when-cross-origin, Permissions-Policy restritivo."
        ))

    if not hdrs.get("hsts_present"):
        vuls.append(_vul(
            next_id(), "HSTS (Strict-Transport-Security) ausente",
            "Alto", "A02 – Cryptographic Failures", "Alta", "curl -I",
            "Sem HSTS, o navegador pode estabelecer conexões HTTP não criptografadas antes do redirect para HTTPS, abrindo janela para ataques de downgrade (SSL stripping).",
            "Adicionar o cabeçalho Strict-Transport-Security: max-age=31536000; includeSubDomains; preload."
        ))

    # ── CSP report-only / unsafe-inline ──────────────────────────────────────
    if hdrs.get("csp_report_only") and not hdrs.get("csp_enforcement"):
        extra = " Diretivas unsafe-inline/unsafe-eval tornam a política ineficaz mesmo se convertida para enforcement mode." if (hdrs.get("csp_unsafe_inline") or hdrs.get("csp_unsafe_eval")) else ""
        vuls.append(_vul(
            next_id(), "CSP em modo report-only — não bloqueia conteúdo malicioso",
            "Médio", "A05 – Security Misconfiguration", "Alta", "curl -I",
            f"O CSP em modo de monitoramento não bloqueia scripts maliciosos injetados via XSS, apenas reporta violações.{extra}",
            "Converter para enforcement mode (Content-Security-Policy em vez de report-only) e remover unsafe-inline/unsafe-eval."
        ))
    elif hdrs.get("csp_enforcement") and (hdrs.get("csp_unsafe_inline") or hdrs.get("csp_unsafe_eval")):
        vuls.append(_vul(
            next_id(), "CSP em enforcement mode mas com unsafe-inline/unsafe-eval",
            "Médio", "A05 – Security Misconfiguration", "Alta", "curl -I",
            "Mesmo em modo de bloqueio, unsafe-inline/unsafe-eval tornam a política ineficaz contra XSS.",
            "Remover unsafe-inline e unsafe-eval. Implementar nonces ou hashes para scripts legítimos."
        ))
    elif not hdrs.get("csp_enforcement") and not hdrs.get("csp_report_only"):
        vuls.append(_vul(
            next_id(), "Content-Security-Policy (CSP) totalmente ausente",
            "Médio", "A05 – Security Misconfiguration", "Alta", "curl -I",
            "Sem CSP, não há camada adicional de defesa contra XSS via controle de quais origens podem executar scripts, estilos ou carregar recursos.",
            "Implementar Content-Security-Policy começando em modo report-only para mapear violações, evoluindo para enforcement mode."
        ))

    # ── CORS irrestrito ────────────────────────────────────────────────────────
    if hdrs.get("cors_wildcard"):
        vuls.append(_vul(
            next_id(), "CORS configurado com Access-Control-Allow-Origin: * (irrestrito)",
            "Médio", "A05 – Security Misconfiguration", "Alta", "curl -I",
            "Qualquer origem pode realizar requisições cross-origin à API, facilitando exfiltração de dados caso existam endpoints autenticados ou sensíveis.",
            "Restringir Access-Control-Allow-Origin a domínios explicitamente autorizados, evitando wildcard em endpoints autenticados."
        ))

    # ── Server header exposto ─────────────────────────────────────────────────
    if hdrs.get("server") and not hdrs.get("cloudflare_detected"):
        vuls.append(_vul(
            next_id(), f"Cabeçalho Server expõe informação do servidor ({hdrs['server']})",
            "Informativo", "A05 – Security Misconfiguration", "Alta", "curl -I",
            "A exposição do cabeçalho Server fornece informações sobre a stack tecnológica, auxiliando reconhecimento por atacantes.",
            "Configurar o servidor para ocultar ou generalizar o cabeçalho Server (ex: ServerTokens Prod no Apache, server_tokens off no Nginx)."
        ))

    # ── X-Powered-By ─────────────────────────────────────────────────────────
    if hdrs.get("x_powered_by"):
        vuls.append(_vul(
            next_id(), f"Tecnologia/versão exposta via X-Powered-By ({hdrs['x_powered_by']})",
            "Baixo", "A05 – Security Misconfiguration", "Alta", "curl -I",
            "A exposição da versão facilita a identificação de CVEs conhecidos associados àquela versão específica.",
            "Remover ou mascarar o cabeçalho X-Powered-By na configuração do servidor ou framework."
        ))

    # ── Cookies sem flags de segurança ────────────────────────────────────────
    if hdrs.get("any_cookie_no_httponly") and not hdrs.get("wp_test_cookie_found"):
        vuls.append(_vul(
            next_id(), "Cookie(s) sem flag HttpOnly",
            "Médio", "A02 – Cryptographic Failures", "Média", "curl / análise de cookies",
            "Cookies legíveis por JavaScript. Em caso de XSS, um atacante pode capturar o cookie para rastreamento ou fixação de sessão.",
            "Adicionar flag HttpOnly em todos os cookies de sessão na configuração do servidor ou framework."
        ))

    # ── ETag inode leak ───────────────────────────────────────────────────────
    etag = vs.get("etag", {})
    if etag.get("inode_leak"):
        vuls.append(_vul(
            next_id(), "ETag vazando inode do servidor (CVE-2003-1418)",
            "Baixo", "A05 – Security Misconfiguration", "Alta", "Nikto / curl",
            "Vaza informações sobre a estrutura interna do sistema de arquivos do servidor, útil para atacantes em reconhecimento avançado.",
            "Desabilitar ETags ou configurá-los sem informações de inode (ex: FileETag None no Apache)."
        ))

    # ── Certificado wildcard ──────────────────────────────────────────────────
    ssl = vs.get("ssl", {})
    if ssl.get("wildcard_cert"):
        vuls.append(_vul(
            next_id(), "Certificado wildcard identificado — subdomínios não mapeados",
            "Informativo", "A05 – Security Misconfiguration", "Alta", "Nikto / openssl",
            "Subdomínios cobertos pelo certificado wildcard mas não mapeados representam superfície de ataque não avaliada.",
            "Enumerar subdomínios via Sublist3r, Amass ou Certificate Transparency Log (crt.sh)."
        ))

    # ── DNSSEC ─────────────────────────────────────────────────────────────────
    if not dns.get("dnssec_enabled"):
        vuls.append(_vul(
            next_id(), "DNSSEC não configurado no domínio",
            "Baixo", "A05 – Security Misconfiguration", "Alta", "dig +dnssec",
            "Domínio vulnerável a DNS Cache Poisoning (Kaminsky Attack), permitindo redirecionamento de usuários para servidores falsos mesmo com HTTPS configurado.",
            "Ativar DNSSEC no painel do provedor de domínio e configurar os registros DS junto ao provedor de DNS."
        ))

    # ── SPF softfail ───────────────────────────────────────────────────────────
    if dns.get("spf_softfail"):
        vuls.append(_vul(
            next_id(), "Registro SPF configurado com softfail (~all)",
            "Baixo", "A05 – Security Misconfiguration", "Alta", "dig TXT",
            "Política SPF com softfail é menos restritiva que hardfail, permitindo que e-mails falsificados em nome do domínio sejam aceitos (apenas marcados como suspeitos), favorecendo phishing.",
            "Migrar a política SPF de ~all para -all após validar todos os remetentes legítimos, complementando com DMARC."
        ))

    # ── CSRF ausente no formulário de login ───────────────────────────────────
    csrf = vs.get("csrf", {})
    if csrf.get("missing_csrf"):
        vuls.append(_vul(
            next_id(), "Ausência de token Anti-CSRF aparente no formulário de login",
            "Médio", "A01 – Broken Access Control", "Média", "Análise de formulário",
            "Permite que um atacante force um usuário autenticado a submeter requisições não intencionais.",
            "Implementar token CSRF (nonce, synchronizer token ou similar) em todos os formulários sensíveis."
        ))

    # ── Rate limiting ausente no login ────────────────────────────────────────
    wplogin_rate = vs.get("wplogin_rate", {})
    if wplogin_rate.get("accessible_200"):
        vuls.append(_vul(
            next_id(), "Página de login sem rate limiting aparente",
            "Alto", "A07 – Identification and Authentication Failures", "Média", "Verificação manual",
            "A ausência de rate limiting permite tentativas ilimitadas de login, facilitando ataques de força bruta e credential stuffing.",
            "Implementar rate limiting (ex: fail2ban, middleware de throttling) e considerar autenticação multifator (2FA/MFA)."
        ))

    # ── E-mails expostos no HTML ──────────────────────────────────────────────
    emails = tech.get("exposed_emails", [])
    if emails:
        vuls.append(_vul(
            next_id(), f"E-mail(s) expostos no código-fonte HTML: {', '.join(emails[:3])}",
            "Baixo", "A05 – Security Misconfiguration", "Alta", "Análise HTML",
            "Vetor direto para phishing direcionado e spam automatizado, pois crawlers capturam e-mails expostos em páginas públicas.",
            "Substituir por formulário de contato protegido por CAPTCHA. Se necessário manter visível, ofuscar via CSS/JavaScript."
        ))

    # ── GTM via noscript ───────────────────────────────────────────────────────
    if tech.get("gtm_id"):
        vuls.append(_vul(
            next_id(), f"Google Tag Manager ({tech['gtm_id']}) implementado",
            "Baixo", "A05 – Security Misconfiguration", "Alta", "Análise HTML",
            "Scripts GTM executam no contexto do domínio principal. Se a conta GTM for comprometida, scripts maliciosos podem ser injetados sem alterar o código-fonte.",
            "Implementar política de aprovação de tags antes de publicação. Considerar CSP para limitar scripts externos."
        ))

    # ── Indexação total habilitada ────────────────────────────────────────────
    robots_meta = tech.get("robots_meta", "") or ""
    if robots_meta and "index" in robots_meta.lower() and "noindex" not in robots_meta.lower():
        vuls.append(_vul(
            next_id(), f"Indexação total habilitada (robots: {robots_meta})",
            "Informativo", "A05 – Security Misconfiguration", "Alta", "Análise de meta tags",
            "Todo o conteúdo é indexável por motores de busca, incluindo potencialmente páginas administrativas ou não destinadas a indexação pública.",
            "Adicionar meta tag noindex em páginas administrativas, de teste ou que contenham dados sensíveis."
        ))

    # ── SRI ausente em scripts externos ───────────────────────────────────────
    if tech.get("external_scripts"):
        vuls.append(_vul(
            next_id(), "Sub Resource Integrity (SRI) ausente em scripts externos",
            "Médio", "A08 – Software and Data Integrity Failures", "Média", "Análise HTML",
            f"Scripts de domínios externos ({', '.join(tech['external_scripts'][:5])}) carregados sem atributo integrity. Comprometimento de qualquer CDN permitiria injeção de código malicioso.",
            "Adicionar atributo integrity (hash SRI) em todos os scripts externos. Gerar hashes via https://www.srihash.org/."
        ))

    # ── Painéis administrativos genéricos expostos ────────────────────────────
    admin_eps = [e for e in ep.get("endpoints", []) if e.get("status") == 200
                 and "administrativo genérico" in e.get("label","")]
    if admin_eps:
        paths = ", ".join(e["path"] for e in admin_eps[:5])
        vuls.append(_vul(
            next_id(), f"Painel(is) administrativo(s) acessível(is): {paths}",
            "Médio", "A07 – Identification and Authentication Failures", "Média", "Enumeração de endpoints",
            "Painéis administrativos expostos publicamente ampliam a superfície de ataque para tentativas de login não autorizado.",
            "Restringir acesso por IP sempre que possível, implementar autenticação multifator e monitorar tentativas de acesso."
        ))

    # ── Arquivos sensíveis genéricos encontrados ──────────────────────────────
    for sf in ep.get("sensitive_files_found", []):
        sev = "Alto" if sf["path"] in ("/.env", "/.git/config", "/.git/HEAD", "/wp-config.php.bak") else "Médio"
        vuls.append(_vul(
            next_id(), f"Arquivo sensível genérico acessível: {sf['path']}",
            sev, "A01 – Broken Access Control", "Alta", "Varredura de arquivos sensíveis",
            f"O arquivo {sf['path']} está publicamente acessível e pode expor credenciais, configurações internas ou código-fonte, dependendo do conteúdo.",
            f"Remover ou bloquear acesso público a {sf['path']} imediatamente via configuração do servidor (.htaccess, nginx.conf) ou removendo o arquivo do diretório público."
        ))

    # ── Uploads acessíveis (genérico) ─────────────────────────────────────────
    if ep.get("uploads_listable"):
        vuls.append(_vul(
            next_id(), f"Diretório de uploads acessível ({ep.get('uploads_path','/uploads/')})",
            "Médio", "A01 – Broken Access Control", "Alta", "Verificação de endpoints",
            "O diretório de uploads pode conter documentos publicados inadvertidamente, sem controle de acesso ou listagem.",
            "Adicionar arquivo index vazio para prevenir listagem. Auditar arquivos existentes em busca de documentos sensíveis."
        ))

    # ── Arquivos sensíveis em uploads (CRÍTICO se houver, LGPD) ──────────────
    for s in vs.get("sensitive_uploads", []):
        vuls.append(_vul(
            next_id(), f"Arquivo sensível exposto publicamente: {s['url'].split('/')[-1]}",
            "Alto", "A01 – Broken Access Control", "Alta", "Varredura de uploads",
            f"CRÍTICO: O arquivo {s['url']} está acessível sem autenticação. Dependendo do conteúdo, pode configurar exposição de dados pessoais e violação de leis de proteção de dados (ex: LGPD art. 14, se envolver menores de idade).",
            "URGENTE: Remover imediatamente o arquivo do diretório público. Auditar todo o diretório de uploads. Avaliar necessidade de notificação à autoridade de proteção de dados competente."
        ))

    return vuls


# ═══════════════════════════════════════════════════════════════════════════
# CAMADA 2 — REGRAS ESPECÍFICAS POR TECNOLOGIA
# ═══════════════════════════════════════════════════════════════════════════
def _wordpress_rules(results: dict, next_id) -> list:
    tech = results.get("tech", {})
    ep   = results.get("endpoints", {})
    vs   = results.get("vulnscan", {})
    hdrs = results.get("headers", {})
    vuls = []

    specific = tech.get("tech_specific", {})
    wp_ver = specific.get("version") or tech.get("wordpress_version")
    if wp_ver:
        vuls.append(_vul(
            next_id(), f"Versão do WordPress {wp_ver} exposta",
            "Baixo", "A05 – Security Misconfiguration", "Alta", "Análise HTML / WhatWeb",
            f"A versão {wp_ver} exposta facilita a busca por CVEs conhecidos específicos dessa release.",
            "Remover indicadores de versão (meta-generator, readme.html, license.txt) ou mantê-los sempre na última versão estável."
        ))

    builder = specific.get("builder_plugin")
    if builder:
        vuls.append(_vul(
            next_id(), f"Versão do {builder} exposta no meta-generator",
            "Médio", "A05 – Security Misconfiguration", "Alta", "Análise HTML",
            f"Facilita identificação de CVEs associados ao {builder} por scanners automatizados.",
            "Remover o meta-generator via functions.php: remove_action('wp_head', 'wp_generator')."
        ))

    xmlrpc = vs.get("xmlrpc", {})
    if xmlrpc.get("exists"):
        status_desc = "bloqueado via WAF/Cloudflare (403)" if xmlrpc.get("blocked") else f"status {xmlrpc.get('status_code')}"
        vuls.append(_vul(
            next_id(), f"xmlrpc.php existe no servidor ({status_desc})",
            "Alto", "A07 – Identification and Authentication Failures", "Alta", "curl / Nikto",
            "Permite ataques de brute force amplificados e pode ser usado em DDoS de amplificação caso a proteção do WAF seja contornada.",
            "Desabilitar via .htaccess: deny from all. Se necessário para integrações legadas, implementar whitelist de IPs."
        ))

    rest_users = ep.get("rest_api_users", {})
    if rest_users.get("exposed"):
        vuls.append(_vul(
            next_id(), "Enumeração de usuários via /wp-json/wp/v2/users",
            "Alto", "A01 – Broken Access Control", "Alta", "Análise de endpoints",
            f"Exposição de {rest_users.get('count',0)} username(s) válido(s), facilitando credential stuffing e brute force direcionado.",
            "Bloquear endpoint via functions.php: remove_action('rest_api_init', 'create_initial_rest_routes', 99) ou plugin de segurança."
        ))

    if not hdrs.get("wp_test_cookie_httponly") and hdrs.get("wp_test_cookie_found"):
        vuls.append(_vul(
            next_id(), "Cookie wordpress_test_cookie sem flag HttpOnly",
            "Médio", "A02 – Cryptographic Failures", "Alta", "Nikto / curl",
            "Cookie legível por JavaScript. Em caso de XSS, pode ser usado para rastreamento ou fixação de sessão.",
            "Adicionar flag HttpOnly via plugin de segurança ou functions.php."
        ))

    if not hdrs.get("wp_test_cookie_samesite") and hdrs.get("wp_test_cookie_found"):
        vuls.append(_vul(
            next_id(), "Cookie wordpress_test_cookie sem atributo SameSite",
            "Baixo", "A05 – Security Misconfiguration", "Alta", "curl",
            "Permite envio do cookie em requisições cross-site, facilitando CSRF.",
            "Adicionar SameSite=Strict via plugin de segurança ou functions.php."
        ))

    if tech.get("wplogin_in_robots"):
        vuls.append(_vul(
            next_id(), "wp-login.php listado no robots.txt (acessível)",
            "Baixo", "A05 – Security Misconfiguration", "Alta", "Análise de robots.txt",
            "Sinaliza explicitamente a existência do endpoint de login para bots e ferramentas automatizadas de ataque.",
            "Remover /wp-login.php do robots.txt."
        ))

    wpcron = next((e for e in ep.get("endpoints", []) if "wp-cron" in e.get("path","") and e.get("status") == 200), None)
    if wpcron:
        vuls.append(_vul(
            next_id(), "/wp-cron.php acessível publicamente (200 OK)",
            "Alto", "A05 – Security Misconfiguration", "Alta", "Enumeração de endpoints",
            "Pode ser abusado para disparar tarefas agendadas sem autenticação, sobrecarregando o servidor (pseudo-DoS).",
            "Bloquear via .htaccess e configurar cron via WP-CLI ou cron job do servidor."
        ))

    wpsettings = next((e for e in ep.get("endpoints", []) if "wp-settings" in e.get("path","") and e.get("status") == 500), None)
    if wpsettings:
        vuls.append(_vul(
            next_id(), "/wp-settings.php retorna erro 500",
            "Médio", "A05 – Security Misconfiguration", "Média", "Enumeração de endpoints",
            "Confirma existência do arquivo e pode revelar informações internas em mensagens de erro detalhadas.",
            "Configurar WP_DEBUG=false em produção."
        ))

    wpcontent_dirs = [e for e in ep.get("endpoints", []) if e.get("path") in ("/wp-content/", "/wp-includes/") and e.get("status") == 200]
    if wpcontent_dirs:
        vuls.append(_vul(
            next_id(), "Diretórios /wp-content e/ou /wp-includes acessíveis",
            "Médio", "A01 – Broken Access Control", "Média", "Enumeração de endpoints",
            "Permite mapeamento completo de plugins, temas e versões, facilitando identificação de CVEs.",
            "Adicionar index.php vazio em /wp-content/ e /wp-includes/."
        ))

    contato_ep = next((e for e in ep.get("endpoints", []) if "contato" in e.get("path","").lower() and e.get("status") == 200), None)
    if contato_ep:
        vuls.append(_vul(
            next_id(), "Possível ausência de CAPTCHA no formulário de contato",
            "Médio", "A07 – Identification and Authentication Failures", "Baixa", "Análise manual",
            "Sem CAPTCHA, formulários públicos permitem automação de spam.",
            "Implementar reCAPTCHA v3 ou hCaptcha no formulário de contato."
        ))

    if tech.get("brevo_webkey"):
        vuls.append(_vul(
            next_id(), "Chave pública Brevo/WonderPush exposta no JavaScript",
            "Informativo", "A05 – Security Misconfiguration", "Alta", "Análise HTML",
            "Chave pública por design, mas deve ser monitorada quanto às permissões no painel do provedor.",
            "Verificar no painel do Brevo/WonderPush se as permissões estão restritas ao mínimo necessário."
        ))

    return vuls


def _laravel_rules(results: dict, next_id) -> list:
    ep = results.get("endpoints", {})
    vuls = []
    env_exposed = next((e for e in ep.get("endpoints", []) if e.get("path") == "/.env" and e.get("status") == 200), None)
    if env_exposed:
        vuls.append(_vul(
            next_id(), "Arquivo .env exposto publicamente (CRÍTICO)",
            "Alto", "A01 – Broken Access Control", "Alta", "Enumeração de endpoints",
            "O arquivo .env do Laravel tipicamente contém credenciais de banco de dados, chaves de API e APP_KEY. Sua exposição permite comprometimento total da aplicação.",
            "URGENTE: Bloquear acesso ao .env via configuração do servidor web. Rotacionar todas as credenciais expostas imediatamente."
        ))
    telescope = next((e for e in ep.get("endpoints", []) if "telescope" in e.get("path","") and e.get("status") == 200), None)
    if telescope:
        vuls.append(_vul(
            next_id(), "Laravel Telescope acessível publicamente",
            "Alto", "A05 – Security Misconfiguration", "Alta", "Enumeração de endpoints",
            "O Telescope expõe requisições, queries SQL, jobs e exceptions da aplicação — informação extremamente sensível para um atacante.",
            "Restringir acesso ao Telescope apenas para ambiente local ou via autenticação/IP whitelist em produção."
        ))
    ignition = next((e for e in ep.get("endpoints", []) if "_ignition" in e.get("path","") and e.get("status") == 200), None)
    if ignition:
        vuls.append(_vul(
            next_id(), "Laravel Ignition (debug) acessível — possível RCE (CVE-2021-3129)",
            "Alto", "A06 – Vulnerable and Outdated Components", "Média", "Enumeração de endpoints",
            "Versões vulneráveis do Ignition permitem Remote Code Execution quando APP_DEBUG=true em produção.",
            "Definir APP_DEBUG=false em produção e atualizar o pacote facade/ignition para a versão mais recente."
        ))
    return vuls


def _django_rules(results: dict, next_id) -> list:
    ep = results.get("endpoints", {})
    vuls = []
    debug_ep = next((e for e in ep.get("endpoints", []) if "__debug__" in e.get("path","") and e.get("status") == 200), None)
    if debug_ep:
        vuls.append(_vul(
            next_id(), "Django Debug Toolbar acessível em produção",
            "Alto", "A05 – Security Misconfiguration", "Alta", "Enumeração de endpoints",
            "Expõe queries SQL, configurações e variáveis de ambiente internas da aplicação.",
            "Definir DEBUG=False em produção e remover django-debug-toolbar do middleware de produção."
        ))
    admin_ep = next((e for e in ep.get("endpoints", []) if e.get("path") == "/admin/" and e.get("status") == 200), None)
    if admin_ep:
        vuls.append(_vul(
            next_id(), "Django Admin acessível na rota padrão /admin/",
            "Médio", "A07 – Identification and Authentication Failures", "Média", "Enumeração de endpoints",
            "A rota padrão facilita ataques de força bruta direcionados especificamente ao painel administrativo.",
            "Alterar a rota padrão do admin para um path customizado e implementar rate limiting e 2FA."
        ))
    return vuls


def _generic_framework_env_rule(results: dict, next_id, tech_id: str) -> list:
    """Regra reutilizável para frameworks que expõem .env (Node, Next.js, etc.)."""
    ep = results.get("endpoints", {})
    vuls = []
    for env_path in ("/.env", "/.env.local", "/.env.production"):
        found = next((e for e in ep.get("endpoints", []) if e.get("path") == env_path and e.get("status") == 200), None)
        if found:
            vuls.append(_vul(
                next_id(), f"Arquivo {env_path} exposto publicamente (CRÍTICO)",
                "Alto", "A01 – Broken Access Control", "Alta", "Enumeração de endpoints",
                f"Arquivos de ambiente tipicamente contêm credenciais, chaves de API e secrets da aplicação {tech_id}.",
                f"URGENTE: Bloquear acesso público a {env_path}. Rotacionar todas as credenciais expostas imediatamente."
            ))
    return vuls


TECH_RULE_HANDLERS = {
    "wordpress": _wordpress_rules,
    "laravel":   _laravel_rules,
    "django":    _django_rules,
}

GENERIC_ENV_TECHS = {"nodejs_express", "nextjs", "nuxt_vue", "rails", "aspnet", "php_generic"}


def run_rule_based_analysis(results: dict) -> list:
    """
    Aplica regras genéricas + regras específicas da tecnologia detectada.
    Sempre produz resultado, mesmo para stacks fora do catálogo (nesse caso
    apenas as regras genéricas se aplicam).
    """
    log("Aplicando motor de regras local (sem IA)...")

    tech = results.get("tech", {})
    primary_id = tech.get("primary_tech_id", "unknown")
    primary_name = tech.get("primary_tech_name", "Desconhecida")

    n = 0
    def next_id():
        nonlocal n
        n += 1
        return f"VUL-{n:03d}"

    vuls = []

    # Camada 1: genéricas (sempre)
    vuls += _generic_rules(results, next_id)

    # Camada 2: específicas por tecnologia
    handler = TECH_RULE_HANDLERS.get(primary_id)
    if handler:
        log(f"Aplicando regras específicas para: {primary_name}")
        vuls += handler(results, next_id)
    elif primary_id in GENERIC_ENV_TECHS:
        log(f"Aplicando regra genérica de .env para: {primary_name}")
        vuls += _generic_framework_env_rule(results, next_id, primary_id)
    else:
        log(f"Sem regras específicas cadastradas para '{primary_id}' — apenas regras genéricas aplicadas")

    log(f"Motor de regras gerou {len(vuls)} vulnerabilidades ({primary_name})")
    return vuls
