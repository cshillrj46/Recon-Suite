"""
Catálogo de Tecnologias — Fingerprints e Perfis de Endpoints
Define como detectar cada tecnologia (CMS, framework, e-commerce ou API) e
quais endpoints/arquivos são relevantes para testar em cada uma.

Cada entrada do catálogo:
{
  "id": identificador único,
  "name": nome de exibição,
  "category": "cms" | "framework" | "ecommerce" | "api",
  "fingerprints": {
      "html":    [regex, ...]               -> procurado no corpo HTML
      "headers": [(header_name, regex)]     -> procurado no valor do cabeçalho
      "cookies": [regex, ...]               -> procurado na string Set-Cookie
  },
  "endpoints": [(path, label), ...],        -> testados se a tech for detectada
  "sensitive_files": [path, ...],           -> arquivos sensíveis específicos
}
"""

import re

TECH_CATALOG = [
    # ════════════════════════════════════════════════════════════════════════
    # CMS
    # ════════════════════════════════════════════════════════════════════════
    {
        "id": "wordpress", "name": "WordPress", "category": "cms",
        "fingerprints": {
            "html": [r"wp-content", r"wp-includes", r'name=["\']generator["\'][^>]+WordPress'],
            "headers": [("link", r"wp-json")],
            "cookies": [r"wordpress_"],
        },
        "endpoints": [
            ("/wp-login.php", "Login WordPress"),
            ("/wp-admin/", "Painel Admin"),
            ("/wp-json/", "REST API"),
            ("/wp-json/wp/v2/users", "Enumeração de Usuários"),
            ("/xmlrpc.php", "XML-RPC"),
            ("/wp-cron.php", "WP-Cron"),
            ("/wp-content/uploads/", "Diretório de Uploads"),
            ("/wp-content/", "WP-Content"),
            ("/wp-includes/", "WP-Includes"),
            ("/wp-settings.php", "WP-Settings"),
            ("/wp-config.php", "WP-Config"),
            ("/wp-load.php", "WP-Load"),
            ("/wp-links-opml.php", "WP-Links-OPML"),
            ("/license.txt", "License.txt (versão WP)"),
            ("/readme.html", "Readme.html (versão WP)"),
            ("/wp-mail.php", "WP-Mail"),
            ("/wp-signup.php", "WP-Signup"),
        ],
        "sensitive_files": ["/wp-config.php.bak", "/wp-config.php.old", "/.wp-config.php.swp"],
    },
    {
        "id": "joomla", "name": "Joomla", "category": "cms",
        "fingerprints": {
            "html": [r"/media/jui/", r"/templates/system/", r'name=["\']generator["\'][^>]+Joomla'],
            "headers": [],
            "cookies": [r"joomla_user_state"],
        },
        "endpoints": [
            ("/administrator/", "Painel Admin"),
            ("/administrator/manifests/files/joomla.xml", "Versão Joomla"),
            ("/configuration.php", "Arquivo de Configuração"),
            ("/configuration.php~", "Backup de Configuração"),
            ("/README.txt", "Readme (versão)"),
            ("/htaccess.txt", "Modelo .htaccess"),
            ("/language/en-GB/en-GB.xml", "Idioma — versão"),
            ("/components/", "Diretório de Componentes"),
            ("/modules/", "Diretório de Módulos"),
            ("/plugins/", "Diretório de Plugins"),
            ("/cache/", "Diretório de Cache"),
            ("/logs/", "Diretório de Logs"),
            ("/tmp/", "Diretório Temporário"),
        ],
        "sensitive_files": ["/configuration.php.bak", "/configuration.php~"],
    },
    {
        "id": "drupal", "name": "Drupal", "category": "cms",
        "fingerprints": {
            "html": [r"/sites/default/files/", r"Drupal\.settings", r'name=["\']generator["\'][^>]+Drupal'],
            "headers": [("x-generator", r"Drupal"), ("x-drupal-cache", r".*")],
            "cookies": [r"SESS[a-f0-9]{32}"],
        },
        "endpoints": [
            ("/user/login", "Login"),
            ("/admin/", "Painel Admin"),
            ("/CHANGELOG.txt", "Changelog (versão)"),
            ("/core/CHANGELOG.txt", "Changelog Core (versão D8+)"),
            ("/sites/default/settings.php", "Configuração"),
            ("/sites/default/files/", "Diretório de Arquivos"),
            ("/jsonapi/", "JSON API"),
            ("/node/1", "Conteúdo Node"),
            ("/INSTALL.txt", "Install (versão)"),
            ("/MAINTAINERS.txt", "Maintainers"),
        ],
        "sensitive_files": ["/sites/default/settings.php.bak"],
    },
    {
        "id": "magento", "name": "Magento", "category": "ecommerce",
        "fingerprints": {
            "html": [r"Mage\.Cookies", r"/skin/frontend/", r"Magento_"],
            "headers": [("x-magento-cache-debug", r".*")],
            "cookies": [],
        },
        "endpoints": [
            ("/admin/", "Painel Admin"),
            ("/downloader/", "Magento Connect"),
            ("/app/etc/local.xml", "Configuração Local (legado)"),
            ("/app/etc/env.php", "Configuração Env (M2)"),
            ("/var/log/", "Logs"),
            ("/RELEASE_NOTES.txt", "Release Notes (versão)"),
            ("/skin/frontend/", "Skin Frontend"),
            ("/media/", "Diretório de Mídia"),
        ],
        "sensitive_files": ["/app/etc/local.xml", "/app/etc/env.php", "/var/export/"],
    },
    {
        "id": "prestashop", "name": "PrestaShop", "category": "ecommerce",
        "fingerprints": {
            "html": [r"PrestaShop", r"/themes/.*?/assets/"],
            "headers": [],
            "cookies": [],
        },
        "endpoints": [
            ("/admin/", "Painel Admin"),
            ("/config/settings.inc.php", "Configuração"),
            ("/install/", "Instalador"),
            ("/modules/", "Módulos"),
        ],
        "sensitive_files": ["/config/settings.inc.php.bak"],
    },
    {
        "id": "shopify", "name": "Shopify", "category": "ecommerce",
        "fingerprints": {
            "html": [r"cdn\.shopify\.com", r"Shopify\.theme"],
            "headers": [("x-shopid", r".*"), ("x-shardid", r".*")],
            "cookies": [r"_shopify_"],
        },
        "endpoints": [
            ("/admin", "Painel Admin"),
            ("/products.json", "Catálogo de Produtos (API pública)"),
            ("/collections.json", "Coleções (API pública)"),
        ],
        "sensitive_files": [],
    },

    # ════════════════════════════════════════════════════════════════════════
    # FRAMEWORKS / LINGUAGENS
    # ════════════════════════════════════════════════════════════════════════
    {
        "id": "laravel", "name": "Laravel", "category": "framework",
        "fingerprints": {
            "html": [r"laravel_session", r"Whoops\\\\Exception"],
            "headers": [("set-cookie", r"laravel_session|XSRF-TOKEN")],
            "cookies": [r"laravel_session", r"XSRF-TOKEN"],
        },
        "endpoints": [
            ("/.env", "Arquivo de Ambiente (CRÍTICO)"),
            ("/telescope", "Laravel Telescope (debug)"),
            ("/_ignition/health-check", "Ignition Debug Endpoint"),
            ("/horizon", "Laravel Horizon"),
            ("/storage/logs/laravel.log", "Log da Aplicação"),
            ("/vendor/", "Diretório Vendor"),
            ("/artisan", "CLI Artisan exposto"),
            ("/api/", "API Routes"),
            ("/.git/config", "Configuração Git"),
        ],
        "sensitive_files": ["/.env", "/.env.bak", "/.env.example", "/storage/logs/laravel.log"],
    },
    {
        "id": "django", "name": "Django", "category": "framework",
        "fingerprints": {
            "html": [r"csrfmiddlewaretoken", r"__debug__"],
            "headers": [("x-frame-options", r"SAMEORIGIN")],
            "cookies": [r"csrftoken", r"sessionid"],
        },
        "endpoints": [
            ("/admin/", "Django Admin"),
            ("/__debug__/", "Django Debug Toolbar"),
            ("/static/admin/", "Static Admin"),
            ("/api/", "Django REST Framework"),
            ("/api/swagger/", "Swagger Docs"),
            ("/.env", "Arquivo de Ambiente"),
            ("/media/", "Diretório de Mídia"),
        ],
        "sensitive_files": ["/.env", "/settings.py", "/db.sqlite3"],
    },
    {
        "id": "rails", "name": "Ruby on Rails", "category": "framework",
        "fingerprints": {
            "html": [r"csrf-param", r"data-turbo"],
            "headers": [("x-powered-by", r"Phusion Passenger"), ("server", r"Phusion")],
            "cookies": [r"_session_id", r"_rails_"],
        },
        "endpoints": [
            ("/rails/info/properties", "Rails Debug Info (CRÍTICO)"),
            ("/rails/mailers", "Action Mailer Preview"),
            ("/.env", "Arquivo de Ambiente"),
            ("/config/database.yml", "Configuração de Banco"),
            ("/config/secrets.yml", "Secrets (legado)"),
            ("/log/development.log", "Log de Desenvolvimento"),
        ],
        "sensitive_files": ["/config/database.yml", "/config/secrets.yml", "/.env"],
    },
    {
        "id": "nextjs", "name": "Next.js / React", "category": "framework",
        "fingerprints": {
            "html": [r"__NEXT_DATA__", r"_next/static", r"data-reactroot"],
            "headers": [("x-powered-by", r"Next\.js")],
            "cookies": [],
        },
        "endpoints": [
            ("/_next/static/", "Assets Next.js"),
            ("/api/", "API Routes"),
            ("/.env.local", "Arquivo de Ambiente Local"),
            ("/sitemap.xml", "Sitemap"),
        ],
        "sensitive_files": ["/.env.local", "/.env.production", "/.next/build-manifest.json"],
    },
    {
        "id": "nuxt_vue", "name": "Nuxt.js / Vue", "category": "framework",
        "fingerprints": {
            "html": [r"__NUXT__", r"data-n-head", r"/_nuxt/"],
            "headers": [], "cookies": [],
        },
        "endpoints": [
            ("/_nuxt/", "Assets Nuxt.js"),
            ("/api/", "API Routes"),
            ("/.env", "Arquivo de Ambiente"),
        ],
        "sensitive_files": ["/.env", "/.nuxt/"],
    },
    {
        "id": "nodejs_express", "name": "Node.js / Express", "category": "framework",
        "fingerprints": {
            "html": [],
            "headers": [("x-powered-by", r"Express")],
            "cookies": [r"connect\.sid"],
        },
        "endpoints": [
            ("/package.json", "Dependências (CRÍTICO)"),
            ("/.env", "Arquivo de Ambiente"),
            ("/node_modules/", "Módulos Node"),
            ("/api/", "API Routes"),
            ("/.git/config", "Configuração Git"),
        ],
        "sensitive_files": ["/.env", "/package.json", "/package-lock.json", "/server.js"],
    },
    {
        "id": "aspnet", "name": "ASP.NET", "category": "framework",
        "fingerprints": {
            "html": [r"__VIEWSTATE", r"__EVENTVALIDATION", r"\.aspx"],
            "headers": [("x-aspnet-version", r".*"), ("x-powered-by", r"ASP\.NET")],
            "cookies": [r"ASP\.NET_SessionId"],
        },
        "endpoints": [
            ("/web.config", "Configuração (CRÍTICO)"),
            ("/Trace.axd", "Trace Handler"),
            ("/elmah.axd", "Elmah Error Log"),
            ("/Default.aspx", "Página Padrão"),
        ],
        "sensitive_files": ["/web.config", "/web.config.bak"],
    },
    {
        "id": "php_generic", "name": "PHP (genérico)", "category": "framework",
        "fingerprints": {
            "html": [],
            "headers": [("x-powered-by", r"PHP")],
            "cookies": [r"PHPSESSID"],
        },
        "endpoints": [
            ("/phpinfo.php", "PHP Info (CRÍTICO se exposto)"),
            ("/info.php", "PHP Info alternativo"),
            ("/.env", "Arquivo de Ambiente"),
            ("/config.php", "Configuração"),
            ("/composer.json", "Dependências Composer"),
        ],
        "sensitive_files": ["/.env", "/config.php.bak", "/phpinfo.php"],
    },

    # ════════════════════════════════════════════════════════════════════════
    # API / SPA puro
    # ════════════════════════════════════════════════════════════════════════
    {
        "id": "rest_api", "name": "API REST genérica", "category": "api",
        "fingerprints": {
            "html": [],
            "headers": [("content-type", r"application/json")],
            "cookies": [],
        },
        "endpoints": [
            ("/api/", "Root da API"),
            ("/swagger.json", "Swagger/OpenAPI Spec"),
            ("/openapi.json", "OpenAPI Spec"),
            ("/api-docs", "Documentação da API"),
            ("/graphql", "GraphQL Endpoint"),
            ("/health", "Health Check"),
            ("/status", "Status Endpoint"),
        ],
        "sensitive_files": [],
    },
]


# ── Checks genéricos (sempre executados, independente da tecnologia) ────────
GENERIC_SENSITIVE_FILES = [
    "/.git/config", "/.git/HEAD", "/.svn/entries",
    "/.env", "/.env.bak", "/.htaccess", "/.htpasswd",
    "/backup.zip", "/backup.sql", "/backup.tar.gz", "/dump.sql", "/database.sql",
    "/web.config", "/Dockerfile", "/docker-compose.yml", "/.dockerignore",
    "/.ssh/id_rsa", "/composer.json", "/composer.lock", "/package.json", "/yarn.lock",
    "/.well-known/security.txt", "/server-status", "/server-info",
]

GENERIC_ADMIN_PATHS = [
    "/admin/", "/administrator/", "/admin.php", "/login/", "/login.php",
    "/cpanel/", "/panel/", "/dashboard/", "/manage/", "/console/", "/portal/", "/backend/",
]


def identify_technology(raw_html: str, raw_headers: dict, raw_cookies: str) -> list:
    """
    Aplica os fingerprints do catálogo contra os dados brutos coletados
    (HTML, cabeçalhos HTTP, cookies) e retorna a lista de tecnologias
    detectadas ordenadas por score de confiança (maior primeiro).
    """
    matches = []

    for entry in TECH_CATALOG:
        fp = entry["fingerprints"]
        score = 0
        evidence = []

        for pattern in fp.get("html", []):
            if raw_html and re.search(pattern, raw_html, re.I):
                score += 2
                evidence.append(f"html:{pattern}")

        for header_name, pattern in fp.get("headers", []):
            val = raw_headers.get(header_name, "") if raw_headers else ""
            if val and re.search(pattern, val, re.I):
                score += 2
                evidence.append(f"header:{header_name}")

        for pattern in fp.get("cookies", []):
            if raw_cookies and re.search(pattern, raw_cookies, re.I):
                score += 2
                evidence.append(f"cookie:{pattern}")

        if score > 0:
            matches.append({
                "id": entry["id"], "name": entry["name"],
                "category": entry["category"], "score": score, "evidence": evidence,
            })

    matches.sort(key=lambda m: -m["score"])
    return matches


def get_tech_profile(tech_id: str) -> dict:
    """Retorna o perfil completo (endpoints, sensitive_files) de uma tecnologia."""
    for entry in TECH_CATALOG:
        if entry["id"] == tech_id:
            return entry
    return {}
