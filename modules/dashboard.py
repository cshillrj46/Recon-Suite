"""
Módulo 8 — Dashboard HTML interativo (Multi-Stack)
Exibe a tecnologia detectada automaticamente em destaque, sem assumir WordPress.
"""

from datetime import datetime
from modules.logger import log

SEV_COLOR = {"ALTO":"#dc3545","MÉDIO":"#fd7e14","BAIXO":"#ffc107","INFORMATIVO":"#0dcaf0","DESCARTADA":"#6c757d","URGENTE":"#7b0000"}
SEV_ORDER = {"URGENTE":0,"ALTO":1,"MÉDIO":2,"BAIXO":3,"INFORMATIVO":4,"DESCARTADA":5}

def _sev_badge(sev):
    color = SEV_COLOR.get(sev.upper(), "#6c757d")
    return f'<span style="background:{color};color:white;padding:2px 8px;border-radius:12px;font-size:12px;font-weight:bold">{sev}</span>'

def _status_badge(code):
    colors = {200:"#28a745",301:"#17a2b8",302:"#17a2b8",403:"#fd7e14",404:"#6c757d",500:"#dc3545"}
    return f'<span style="background:{colors.get(code,"#6c757d")};color:white;padding:2px 6px;border-radius:4px;font-size:11px">{code}</span>'


def generate_dashboard(results: dict, output_path):
    log("Gerando dashboard HTML...")

    domain = results.get("domain","")
    date   = results.get("date", datetime.now().strftime("%d/%m/%Y"))
    team   = results.get("team","")
    dns    = results.get("dns", {})
    hdrs   = results.get("headers", {})
    tech   = results.get("tech", {})
    ep     = results.get("endpoints", {})
    vs     = results.get("vulnscan", {})
    vuls   = sorted(results.get("vulnerabilities",[]), key=lambda v: SEV_ORDER.get(v.get("severity","").upper(),99))

    tech_name = tech.get("primary_tech_name", "Desconhecida")
    tech_cat  = tech.get("primary_tech_category", "")
    tech_ver  = tech.get("tech_specific", {}).get("version","")
    tech_full = f"{tech_name} {tech_ver}".strip() if tech_ver else tech_name

    altas  = sum(1 for v in vuls if v.get("severity","").upper() in ("ALTO","URGENTE"))
    medias = sum(1 for v in vuls if v.get("severity","").upper() == "MÉDIO")
    baixas = sum(1 for v in vuls if v.get("severity","").upper() == "BAIXO")
    infos  = sum(1 for v in vuls if v.get("severity","").upper() == "INFORMATIVO")

    vul_rows = ""
    for v in vuls:
        sev = v.get("severity","")
        vul_rows += f"""
        <tr>
          <td><strong>{v.get('id','')}</strong></td>
          <td>{v.get('title','')}</td>
          <td>{_sev_badge(sev)}</td>
          <td><small>{v.get('owasp','')}</small></td>
          <td><small>{v.get('certainty','')}</small></td>
          <td><small>{v.get('tool','')}</small></td>
        </tr>
        <tr class="detail-row" id="detail-{v.get('id','').replace('-','')}">
          <td colspan="6" style="background:#f8f9fa;padding:16px">
            <strong>Impacto:</strong> {v.get('impact','N/A')}<br><br>
            <strong>Correção:</strong> {v.get('remediation','N/A')}
          </td>
        </tr>"""

    ep_rows = ""
    for e in ep.get("endpoints",[]):
        st = e.get("status",0)
        if st in (200,301,302,403,500):
            ep_rows += f"<tr><td>{e.get('path','')}</td><td>{e.get('label','')}</td><td>{_status_badge(st)}</td></tr>"

    hdr_rows = ""
    for f in hdrs.get("findings",[]):
        sev = f.get("severity","OK")
        color = "#dc3545" if sev in ("Alto","Médio") else ("#ffc107" if sev=="Baixo" else ("#28a745" if sev=="OK" else "#17a2b8"))
        icon = "✔" if sev=="OK" else "✖"
        hdr_rows += f'<tr><td>{f["header"]}</td><td style="color:{color}">{icon} {f["status"]}</td><td>{sev}</td></tr>'

    tech_matches_html = ""
    for m in tech.get("tech_matches", [])[:6]:
        tech_matches_html += f'<span class="tech-tag">{m["name"]}<span class="tv">{m["score"]}</span></span>'

    sensitive_html = ""
    for sf in ep.get("sensitive_files_found", []):
        sensitive_html += f'<div class="alert-box"><strong>⚠ ARQUIVO SENSÍVEL:</strong> {sf["path"]}</div>'
    for s in vs.get("sensitive_uploads", []):
        sensitive_html += f'<div class="alert-box"><strong>⚠ ARQUIVO SENSÍVEL EM UPLOADS:</strong> <a href="{s["url"]}" target="_blank">{s["url"]}</a></div>'

    nikto_html = ""
    for n in vs.get("nikto_findings",[])[:20]:
        nikto_html += f"<li>{n}</li>"

    html = f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Pentest Dashboard — {domain}</title>
<style>
* {{ box-sizing:border-box; margin:0; padding:0; }}
body {{ font-family:'Segoe UI',Arial,sans-serif; background:#0f1117; color:#e2e8f0; min-height:100vh; }}
header {{ background:linear-gradient(135deg,#1a3c6e 0%,#0d2137 100%); padding:24px 32px; border-bottom:3px solid #3b82f6; }}
header h1 {{ font-size:22px; color:#fff; margin-bottom:4px; }}
header p {{ color:#94a3b8; font-size:13px; }}
.tech-banner {{ background:#162032; padding:14px 32px; border-bottom:1px solid #2d3748; display:flex; align-items:center; gap:10px; flex-wrap:wrap; }}
.tech-tag {{ display:inline-block; background:#2d3748; padding:4px 10px; border-radius:6px; font-size:12px; margin:2px; }}
.tech-tag .tv {{ color:#60a5fa; margin-left:6px; font-weight:bold; }}
.container {{ max-width:1400px; margin:0 auto; padding:24px 32px; }}
.grid-4 {{ display:grid; grid-template-columns:repeat(4,1fr); gap:16px; margin-bottom:24px; }}
.grid-2 {{ display:grid; grid-template-columns:1fr 1fr; gap:20px; margin-bottom:24px; }}
.card {{ background:#1e2535; border-radius:12px; padding:20px; border:1px solid #2d3748; }}
.stat-card {{ text-align:center; border-top:4px solid; }}
.stat-card h2 {{ font-size:42px; font-weight:800; margin:8px 0; }}
.stat-card p {{ font-size:13px; color:#94a3b8; text-transform:uppercase; letter-spacing:0.05em; }}
.card h3 {{ font-size:14px; color:#94a3b8; text-transform:uppercase; letter-spacing:0.05em; margin-bottom:16px; padding-bottom:8px; border-bottom:1px solid #2d3748; }}
table {{ width:100%; border-collapse:collapse; font-size:13px; }}
th {{ background:#2d3748; color:#94a3b8; text-transform:uppercase; font-size:11px; padding:10px 12px; text-align:left; }}
td {{ padding:10px 12px; border-bottom:1px solid #2d3748; vertical-align:top; }}
tr:hover td {{ background:#263044; cursor:pointer; }}
.detail-row.hidden td {{ display:none; }}
.alert-box {{ background:#7f1d1d; border:1px solid #dc2626; border-radius:8px; padding:12px 16px; margin-bottom:10px; font-size:13px; }}
.info-item {{ font-size:13px; line-height:1.6; }}
.info-item strong {{ color:#94a3b8; }}
ul {{ padding-left:20px; line-height:1.8; font-size:13px; color:#cbd5e1; }}
a {{ color:#60a5fa; }}
@media (max-width:768px) {{ .grid-4,.grid-2 {{ grid-template-columns:1fr; }} }}
</style>
</head>
<body>
<header>
  <h1>🔍 Pentest Dashboard — {domain}</h1>
  <p>Equipe: {team} &nbsp;|&nbsp; Data: {date} &nbsp;|&nbsp; OWASP WSTG v4.2</p>
</header>
<div class="tech-banner">
  <strong>🔧 Stack detectada:</strong> {tech_full} <em>({tech_cat or 'categoria não classificada'})</em>
  {tech_matches_html}
</div>

<div class="container">
  <div class="grid-4">
    <div class="card stat-card" style="border-color:#dc3545"><p>Alta Severidade</p><h2 style="color:#dc3545">{altas}</h2></div>
    <div class="card stat-card" style="border-color:#fd7e14"><p>Média Severidade</p><h2 style="color:#fd7e14">{medias}</h2></div>
    <div class="card stat-card" style="border-color:#ffc107"><p>Baixa Severidade</p><h2 style="color:#ffc107">{baixas}</h2></div>
    <div class="card stat-card" style="border-color:#0dcaf0"><p>Informativo</p><h2 style="color:#0dcaf0">{infos}</h2></div>
  </div>

  {f'<div class="section">{sensitive_html}</div>' if sensitive_html else ''}

  <div class="card section" style="margin-bottom:24px">
    <h3>📋 Vulnerabilidades Identificadas ({len(vuls)} total)</h3>
    <p style="font-size:12px;color:#64748b;margin-bottom:12px">Clique em uma linha para ver impacto e correção</p>
    <table><thead><tr><th>ID</th><th>Vulnerabilidade</th><th>Severidade</th><th>OWASP</th><th>Certeza</th><th>Ferramenta</th></tr></thead>
    <tbody id="vulTable">{vul_rows}</tbody></table>
  </div>

  <div class="grid-2">
    <div class="card"><h3>🌐 DNS / WHOIS</h3>
      <div class="info-item">
        <p><strong>IPs:</strong> {', '.join(dns.get('a_records',[]))}</p>
        <p><strong>NS:</strong> {', '.join(dns.get('ns_records',[]))}</p>
        <p><strong>CDN:</strong> {dns.get('cdn','N/A')}</p>
        <p><strong>DNSSEC:</strong> {'<span style="color:#28a745">ATIVO</span>' if dns.get('dnssec_enabled') else '<span style="color:#dc3545">INATIVO</span>'}</p>
      </div>
    </div>
    <div class="card"><h3>🔧 Detalhes da Stack</h3>
      <div class="info-item">
        <p><strong>Tecnologia:</strong> {tech_full}</p>
        <p><strong>jQuery:</strong> {tech.get('jquery_version','N/A')}</p>
        <p><strong>GTM:</strong> {tech.get('gtm_id','Não detectado')}</p>
        <p><strong>E-mails expostos:</strong> {tech.get('exposed_emails','Nenhum')}</p>
      </div>
    </div>
  </div>

  <div class="grid-2">
    <div class="card"><h3>🔒 Cabeçalhos HTTP</h3>
      <table><thead><tr><th>Cabeçalho</th><th>Status</th><th>Severidade</th></tr></thead><tbody>{hdr_rows}</tbody></table>
    </div>
    <div class="card"><h3>🗂️ Endpoints Testados</h3>
      <table><thead><tr><th>Path</th><th>Descrição</th><th>Status</th></tr></thead><tbody>{ep_rows}</tbody></table>
    </div>
  </div>

  {f'<div class="card section"><h3>🛡️ Achados Nikto</h3><ul>{nikto_html}</ul></div>' if nikto_html else ''}

  <p style="text-align:center;color:#475569;font-size:12px;margin-top:32px">
    Gerado automaticamente por Recon Suite &nbsp;|&nbsp; {date}
  </p>
</div>

<script>
document.querySelectorAll('#vulTable tr:not(.detail-row)').forEach(row => {{
  row.addEventListener('click', () => {{
    const next = row.nextElementSibling;
    if (next && next.classList.contains('detail-row')) next.classList.toggle('hidden');
  }});
}});
document.querySelectorAll('.detail-row').forEach(r => r.classList.add('hidden'));
</script>
</body></html>"""

    with open(str(output_path), "w", encoding="utf-8") as f:
        f.write(html)
    log(f"Dashboard salvo: {output_path}")
