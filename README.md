# Recon Suite — Automação de Pentest Multi-Tecnologia

Ferramenta de automação completa para reconhecimento, varredura e classificação
de vulnerabilidades, com **detecção automática de tecnologia** — não assume
WordPress nem nenhuma stack fixa. Funciona com CMS (WordPress, Joomla,
Drupal, Magento, PrestaShop, Shopify), frameworks (Laravel, Django, Rails,
Next.js, Nuxt, Node/Express, ASP.NET, PHP genérico) e APIs REST.

---

## Como a detecção automática funciona

```
Domínio
  │
  ├─[1] DNS / WHOIS / DNSSEC
  ├─[2] Cabeçalhos HTTP
  ├─[3] Fingerprinting        → identifica a stack via catálogo de assinaturas
  │                              (HTML, headers, cookies) com score de confiança
  ├─[4] Endpoints             → combina checks GENÉRICOS (admin paths, arquivos
  │                              sensíveis universais) + checks ESPECÍFICOS da
  │                              stack detectada (ex: /wp-json/ só se WordPress,
  │                              /.env e /telescope só se Laravel)
  ├─[5] Varredura de VULs     → checks genéricos (TLS, ETag, CSRF) + específicos
  ├─[6] Classificação de VULs → Claude → Gemini → Motor de Regras
  │                              (regras genéricas + regras por tecnologia)
  ├─[7] Relatório Word ABNT   → texto adaptado dinamicamente à stack detectada
  └─[8] Dashboard HTML        → exibe a stack identificada em destaque
```

### Tecnologias no catálogo (`modules/tech_catalog.py`)

| Categoria   | Tecnologias |
|-------------|-------------|
| CMS         | WordPress, Joomla, Drupal |
| E-commerce  | Magento, PrestaShop, Shopify |
| Framework   | Laravel, Django, Ruby on Rails, Next.js/React, Nuxt.js/Vue, Node.js/Express, ASP.NET, PHP genérico |
| API         | API REST genérica (Swagger/OpenAPI, GraphQL) |

Adicionar uma nova tecnologia é só inserir uma entrada no `TECH_CATALOG` —
fingerprints (regex de HTML/headers/cookies) + lista de endpoints + arquivos
sensíveis. Nenhum outro módulo precisa ser tocado.

### Regras de vulnerabilidade — duas camadas (`modules/rule_engine.py`)

1. **Genéricas** — sempre avaliadas, independem da tecnologia: HSTS, CSP,
   CORS, cookies, DNSSEC, SPF, ETag, certificado wildcard, painéis admin
   genéricos expostos, arquivos sensíveis universais (`.env`, `.git/config`,
   backups), rate limiting e CSRF no login.
2. **Específicas por stack** — disparam apenas se aquela tecnologia foi
   detectada. Hoje implementadas: WordPress (9 regras), Laravel (3 regras),
   Django (2 regras), além de uma regra reutilizável de `.env` para
   Node/Next/Nuxt/Rails/ASP.NET/PHP.

---

## Instalação

### Dependências Python (obrigatórias)
```bash
pip install python-docx requests beautifulsoup4 --break-system-packages
```

### Ferramentas do sistema (Kali/Ubuntu/WSL)
```bash
sudo apt install whois dnsutils curl whatweb nikto gobuster
```

### IA para classificação de VULs (OPCIONAL)
A ferramenta funciona sem nenhuma IA configurada, usando o motor de regras local.

```bash
# Opcional: Claude
pip install anthropic --break-system-packages
export ANTHROPIC_API_KEY="sua-chave"

# Opcional: Gemini (tier gratuito em aistudio.google.com/apikey)
pip install google-generativeai --break-system-packages
export GEMINI_API_KEY="sua-chave"
```

---

## Uso

```bash
# Básico — detecta a tecnologia automaticamente, relatório sem cabeçalho institucional
python3 recon_suite.py exemplo.com.br

# Com dados de equipe (opcional — qualquer contexto: empresa, equipe de pentest, etc.)
python3 recon_suite.py exemplo.com.br --team "Equipe X" --members "Nome1 - RM 111, Nome2 - RM 222"

# Contexto acadêmico/institucional (opcional — só aparece na capa se informado)
python3 recon_suite.py exemplo.com.br \
  --institution "Nome da Instituição" --course "Nome do Curso" --advisor "Nome do Orientador"

# Forçar motor de regras (sem IA)
python3 recon_suite.py exemplo.com.br --skip-ai

# Rápido (sem Gobuster/Nikto)
python3 recon_suite.py exemplo.com.br --skip-gobuster --skip-nikto
```

---

## Saídas geradas

```
output/
├── Relatorio_Pentest_{dominio}_{timestamp}.docx
└── Dashboard_{dominio}_{timestamp}.html

results/
└── {dominio}_{timestamp}.json
```

O relatório e o dashboard exibem explicitamente qual tecnologia foi
detectada e com qual nível de confiança, junto das demais candidatas
avaliadas pelo catálogo — tornando o processo auditável.

---

## Módulos

| Arquivo                     | Responsabilidade |
|------------------------------|------------------|
| `recon_suite.py`              | Orquestra todos os módulos |
| `modules/tech_catalog.py`    | Catálogo de fingerprints e perfis de endpoints por tecnologia |
| `modules/dns_whois.py`       | WHOIS, dig (genérico) |
| `modules/http_headers.py`    | Cabeçalhos HTTP (genérico) |
| `modules/tech_finger.py`     | Detecção automática de stack via catálogo |
| `modules/endpoint_enum.py`   | Endpoints genéricos + específicos da stack |
| `modules/vuln_scan.py`       | Nikto + checks genéricos + específicos adaptados ao path da stack |
| `modules/rule_engine.py`     | Motor de regras: camada genérica + camada por tecnologia |
| `modules/ai_analysis.py`     | Orquestra Claude → Gemini → motor de regras |
| `modules/report_gen.py`      | Relatório Word ABNT com texto adaptado à stack |
| `modules/dashboard.py`       | Dashboard HTML com stack detectada em destaque |
| `modules/logger.py`          | Output colorido no terminal |

---

## Estendendo o catálogo

Para adicionar suporte a uma nova tecnologia, edite `modules/tech_catalog.py`:

```python
{
    "id": "minha_tech", "name": "Minha Tecnologia", "category": "framework",
    "fingerprints": {
        "html": [r"assinatura_no_html"],
        "headers": [("nome-do-header", r"padrao")],
        "cookies": [r"nome_do_cookie"],
    },
    "endpoints": [("/rota/sensivel", "Descrição")],
    "sensitive_files": ["/arquivo/sensivel.ext"],
}
```

Para adicionar regras específicas dessa tecnologia, crie uma função
`_minha_tech_rules(results, next_id)` em `rule_engine.py` e registre em
`TECH_RULE_HANDLERS["minha_tech"] = _minha_tech_rules`.

---

## Aviso legal

Esta ferramenta foi desenvolvida para fins educacionais. Use apenas em
ambientes autorizados. O uso não autorizado contra sistemas de terceiros é ilegal.
