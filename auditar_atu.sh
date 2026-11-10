#!/bin/bash
# --- Script de Auditoría Diaria - Grupo ATU (Definitivo y Optimizado) ---

TARGET_DOMAIN="grupoatu.com"
CURRENT_DIR="$(pwd)"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

SUBDOMAINS_FILE="$CURRENT_DIR/subdominios_grupoatu.txt"
BASE_MASTER="$CURRENT_DIR/subdominios_base.txt"
REPORT_TXT="$CURRENT_DIR/informe_diario_$TIMESTAMP.txt"
REPORT_HTML="$CURRENT_DIR/informe_diario_$TIMESTAMP.html"
NMAP_OUT="$CURRENT_DIR/nmap_$TIMESTAMP.xml"
LOG_FILE="$CURRENT_DIR/auditoria.log"

echo "[*] Iniciando auditoría para $TARGET_DOMAIN..." | tee -a "$LOG_FILE"

# 1. Recopilación de subdominios
python3 -c '
import urllib.request, json, ssl, os
domains = set()
master_file = "subdominios_base.txt"
if os.path.exists(master_file):
    with open(master_file, "r") as f:
        for line in f:
            d = line.strip().lower()
            if d: domains.add(d)

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

try:
    url = "https://crt.sh/?q=%.grupoatu.com&output=json"
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=15, context=ctx) as res:
        for entry in json.loads(res.read().decode()):
            nv = entry.get("name_value", "")
            for line in nv.split("\n"):
                l = line.strip().lower().replace("*.", "")
                if l and "grupoatu.com" in l: domains.add(l)
except Exception:
    pass

with open("subdominios_grupoatu.txt", "w") as out:
    for d in sorted(domains): out.write(d + "\n")
'

[ ! -f "$SUBDOMAINS_FILE" ] && touch "$SUBDOMAINS_FILE"
TOTAL_SUBS=$(wc -l < "$SUBDOMAINS_FILE")

DATOS_TABLA_HTML=""
IPS_ACTIVAS=0
TOTAL_CRITICOS=0
TOTAL_MEDIOS=0
TOTAL_VIGENTES=0
TOTAL_INACTIVOS=0

# 2. Procesamiento de subdominios y estados
while read -r subdomain; do
    [ -z "$subdomain" ] && continue
    SUB_IP=$(getent hosts "$subdomain" | awk '{print $1}' | head -n 1)
    [ -z "$SUB_IP" ] && SUB_IP="No resuelta"
    [ "$SUB_IP" != "No resuelta" ] && IPS_ACTIVAS=$((IPS_ACTIVAS + 1))

    EXPIRY_DATE=$(timeout 2 openssl s_client -connect "$subdomain:443" -servername "$subdomain" </dev/null 2>/dev/null | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2)

    if [ -n "$EXPIRY_DATE" ]; then
        EXPR_EPOCH=$(date -d "$EXPIRY_DATE" +%s 2>/dev/null || echo 0)
        NOW_EPOCH=$(date +%s)
        if [ "$EXPR_EPOCH" -gt "$NOW_EPOCH" ]; then
            ESTADO="SSL VIGENTE"
            BADGE_CLASS="badge-success"
            DETALLES="Expira: $EXPIRY_DATE"
            TOTAL_VIGENTES=$((TOTAL_VIGENTES + 1))
        else
            ESTADO="CERTIFICADO EXPIRADO"
            BADGE_CLASS="badge-danger"
            DETALLES="Caducado el $EXPIRY_DATE"
            TOTAL_CRITICOS=$((TOTAL_CRITICOS + 1))
        fi
    else
        if [ "$SUB_IP" != "No resuelta" ]; then
            ESTADO="SIN HTTPS"
            BADGE_CLASS="badge-warning"
            DETALLES="Puerto 443 cerrado o sin cifrado"
            TOTAL_MEDIOS=$((TOTAL_MEDIOS + 1))
        else
            ESTADO="INACTIVO"
            BADGE_CLASS="badge-secondary"
            DETALLES="Sin resolución DNS"
            TOTAL_INACTIVOS=$((TOTAL_INACTIVOS + 1))
        fi
    fi

    DATOS_TABLA_HTML="${DATOS_TABLA_HTML}<tr><td><strong>${subdomain}</strong></td><td><code>${SUB_IP}</code></td><td><span class=\"badge ${BADGE_CLASS}\">${ESTADO}</span></td><td><small>${DETALLES}</small></td></tr>"
done < "$SUBDOMAINS_FILE"

# 3. Escaneo Nmap
GATEWAY_IP=$(ip route show | awk '/default/ {print $3}' | head -n 1)
[ -z "$GATEWAY_IP" ] && GATEWAY_IP="192.168.1.1"
SUBNET_TARGET=$(echo "$GATEWAY_IP" | awk -F'.' '{print $1"."$2"."$3".0/24"}')
nmap -sS -sV -O --osscan-limit -T4 -oX "$NMAP_OUT" "$SUBNET_TARGET" >/dev/null 2>&1

NMAP_HTML_CARDS=$(python3 -c '
import xml.etree.ElementTree as ET
import sys
out = ""
try:
    tree = ET.parse(sys.argv[1])
    for host in tree.getroot().findall("host"):
        status = host.find("status")
        if status is None or status.get("state") != "up": continue
        ip = host.find("address[@addrtype=\"ipv4\"]")
        ip_addr = ip.get("addr") if ip is not None else "Desconocida"
        ports = ""
        for p in host.findall(".//port"):
            if p.find("state").get("state") != "open": continue
            pid = p.get("portid")
            proto = p.get("protocol")
            s = p.find("service")
            sname = s.get("name", "-") if s is not None else "-"
            ports += f"<tr><td><strong>{pid}/{proto}</strong></td><td><span class=\"badge badge-success\">Abierto</span></td><td>{sname}</td></tr>"
        if not ports: ports = "<tr><td colspan=\"3\" style=\"color:#8898aa;text-align:center;\">Sin puertos abiertos expuestos</td></tr>"
        out += f"<div class=\"card host-card\"><h3>Host: {ip_addr}</h3><table class=\"table\"><thead><tr><th>Puerto</th><th>Estado</th><th>Servicio</th></tr></thead><tbody>{ports}</tbody></table></div>"
except Exception as e:
    out = f"<p>Error procesando Nmap: {e}</p>"
print(out)
' "$NMAP_OUT")

# 4. Generación de informe HTML seguro (delimitado con EOF sin comillas para expandir variables correctamente)
cat << EOF_HTML > "$REPORT_HTML"
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reporte Ejecutivo de Ciberseguridad y Mitigación - Grupo ATU</title>
    <style>
        :root {
            --bg-main: #0f172a;
            --bg-card: #1e293b;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --border-color: #334155;
            --accent-blue: #3b82f6;
            --success: #22c55e;
            --warning: #f59e0b;
            --danger: #ef4444;
            --secondary: #64748b;
        }

        body {
            font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
            background-color: var(--bg-main);
            color: var(--text-main);
            margin: 0;
            padding: 30px;
            line-height: 1.6;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
        }

        .header {
            background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
            padding: 30px;
            border-radius: 12px;
            border: 1px solid var(--border-color);
            margin-bottom: 30px;
            box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.3);
        }

        .header h1 {
            margin: 0 0 10px 0;
            font-size: 26px;
            color: var(--text-main);
            letter-spacing: -0.5px;
        }

        .header p {
            margin: 0;
            color: var(--text-muted);
            font-size: 14px;
        }

        .kpi-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }

        .kpi-card {
            background-color: var(--bg-card);
            padding: 20px;
            border-radius: 10px;
            border: 1px solid var(--border-color);
            text-align: center;
        }

        .kpi-card .number {
            font-size: 28px;
            font-weight: 700;
            margin-bottom: 5px;
        }

        .kpi-card .label {
            font-size: 12px;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .card {
            background-color: var(--bg-card);
            border-radius: 12px;
            border: 1px solid var(--border-color);
            padding: 25px;
            margin-bottom: 30px;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.2);
        }

        .card h2 {
            margin-top: 0;
            font-size: 18px;
            color: var(--accent-blue);
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 12px;
            margin-bottom: 20px;
        }

        .mitigation-list {
            list-style: none;
            padding: 0;
            margin: 0;
        }

        .mitigation-item {
            background: rgba(15, 23, 42, 0.6);
            border-left: 4px solid var(--accent-blue);
            padding: 15px 20px;
            margin-bottom: 15px;
            border-radius: 0 8px 8px 0;
            border-top: 1px solid var(--border-color);
            border-right: 1px solid var(--border-color);
            border-bottom: 1px solid var(--border-color);
        }

        .mitigation-item.critical { border-left-color: var(--danger); }
        .mitigation-item.warning { border-left-color: var(--warning); }
        .mitigation-item.success { border-left-color: var(--success); }

        .mitigation-title {
            font-weight: 600;
            font-size: 15px;
            color: var(--text-main);
            margin-bottom: 5px;
        }

        .mitigation-desc {
            font-size: 13px;
            color: var(--text-muted);
            margin: 0;
        }

        .table {
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
        }

        .table th {
            background-color: #0f172a;
            color: var(--text-muted);
            text-transform: uppercase;
            font-size: 11px;
            letter-spacing: 0.5px;
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
        }

        .table td {
            padding: 12px 15px;
            border-bottom: 1px solid var(--border-color);
        }

        .table tbody tr:hover {
            background-color: rgba(255, 255, 255, 0.02);
        }

        code {
            font-family: 'Fira Code', monospace;
            background: rgba(255, 255, 255, 0.05);
            padding: 2px 6px;
            border-radius: 4px;
            color: #38bdf8;
        }

        .badge {
            display: inline-block;
            padding: 4px 10px;
            border-radius: 20px;
            font-size: 11px;
            font-weight: 600;
            text-transform: uppercase;
        }

        .badge-success { background-color: rgba(34, 197, 94, 0.15); color: var(--success); border: 1px solid rgba(34, 197, 94, 0.3); }
        .badge-warning { background-color: rgba(245, 158, 11, 0.15); color: var(--warning); border: 1px solid rgba(245, 158, 11, 0.3); }
        .badge-danger { background-color: rgba(239, 68, 68, 0.15); color: var(--danger); border: 1px solid rgba(239, 68, 68, 0.3); }
        .badge-secondary { background-color: rgba(100, 116, 139, 0.15); color: var(--secondary); border: 1px solid rgba(100, 116, 139, 0.3); }

        .host-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
            gap: 20px;
        }

        .host-card h3 {
            margin-top: 0;
            font-size: 15px;
            color: #38bdf8;
            margin-bottom: 15px;
        }

        .footer {
            text-align: center;
            font-size: 12px;
            color: var(--text-muted);
            margin-top: 40px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Informe Ejecutivo de Ciberseguridad y Mitigación</h1>
            <p>Organización: <strong>Grupo ATU</strong> | Fecha de Emisión: $(date +"%Y-%m-%d %H:%M:%S")</p>
        </div>

        <div class="kpi-grid">
            <div class="kpi-card">
                <div class="number" style="color: var(--accent-blue);">${TOTAL_SUBS}</div>
                <div class="label">Subdominios</div>
            </div>
            <div class="kpi-card">
                <div class="number" style="color: #38bdf8;">${IPS_ACTIVAS}</div>
                <div class="label">IPs Activas</div>
            </div>
            <div class="kpi-card">
                <div class="number" style="color: var(--success);">${TOTAL_VIGENTES}</div>
                <div class="label">SSL Vigentes</div>
            </div>
            <div class="kpi-card">
                <div class="number" style="color: var(--warning);">${TOTAL_MEDIOS}</div>
                <div class="label">Sin HTTPS</div>
            </div>
            <div class="kpi-card">
                <div class="number" style="color: var(--danger);">${TOTAL_CRITICOS}</div>
                <div class="label">Expirados</div>
            </div>
        </div>

        <div class="card">
            <h2>1. Recomendaciones Estratégicas y Plan de Mitigación</h2>
            <ul class="mitigation-list">
                <li class="mitigation-item critical">
                    <div class="mitigation-title">Gestión de Certificados SSL/TLS Expirados (Prioridad Alta)</div>
                    <p class="mitigation-desc">Renovar de inmediato los certificados digitales que se encuentren vencidos o próximos a expirar. Se recomienda automatizar la emisión y renovación mediante Let's Encrypt (Certbot) para evitar interrupciones de servicio y alertas de seguridad a los usuarios.</p>
                </li>
                <li class="mitigation-item warning">
                    <div class="mitigation-title">Forzar Redirección HTTPS Obligatoria (HSTS)</div>
                    <p class="mitigation-desc">Implementar redirecciones automáticas de HTTP (puerto 80) a HTTPS (puerto 443) en todos los subdominios activos identificados sin cifrado. Habilitar la cabecera HTTP Strict Transport Security (HSTS) en los servidores web (Nginx/Apache).</p>
                </li>
                <li class="mitigation-item success">
                    <div class="mitigation-title">Depuración y Limpieza de Registros DNS Huérfanos</div>
                    <p class="mitigation-desc">Revisar los subdominios que devuelven estado <code>INACTIVO</code> (sin resolución DNS). Si dichos servicios ya no se utilizan, se deben eliminar los registros de las zonas DNS públicas para prevenir ataques de secuestro de subdominios (Subdomain Takeover).</p>
                </li>
                <li class="mitigation-item">
                    <div class="mitigation-title">Restricción de Acceso Perimetral y Endpoints Sensibles</div>
                    <p class="mitigation-desc">Asegurar que los servicios expuestos en la red local o paneles de administración no sean accesibles directamente desde Internet sin una capa previa de autenticación multifactor (MFA) o VPN corporativa.</p>
                </li>
            </ul>
        </div>

        <div class="card">
            <h2>2. Estado Detallado de Subdominios e Infraestructura Externa</h2>
            <table class="table">
                <thead>
                    <tr>
                        <th>Subdominio</th>
                        <th>Dirección IP</th>
                        <th>Estado de Seguridad</th>
                        <th>Detalles SSL / Expiración</th>
                    </tr>
                </thead>
                <tbody>
                    ${DATOS_TABLA_HTML}
                </tbody>
            </table>
        </div>

        <div class="card">
            <h2>3. Análisis Perimetral de Red Local (Subred ${SUBNET_TARGET})</h2>
            <div class="host-grid">
                ${NMAP_HTML_CARDS}
            </div>
        </div>

        <div class="footer">
            <p>Documento de auditoría y mitigación generado automáticamente para Grupo ATU.</p>
        </div>
    </div>
</body>
</html>
EOF_HTML

chmod +x auditar_atu.sh
echo "[✓] Script corregido y actualizado correctamente."
