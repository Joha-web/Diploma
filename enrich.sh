8000 200 OK
Server: SimpleHTTP/0.6 Python/3.13.5
Date: Mon, 06 Apr 2026 09:43:37 GMT
Content-type: text/x-sh
Content-Length: 33794
Last-Modified: Mon, 06 Apr 2026 09:43:18 GMT

#!/usr/bin/env bash
# =============================================================================
#  enrich.sh — Обогащение данных после recon.sh
#  Модули:
#    1. Port Scan   — nmap --top-ports 1000
#    2. Technologies — whatweb + httpx --tech-detect + wafw00f
#
#  Запуск:
#    bash enrich.sh <recon_output_dir>
#
#  Зависимости (open-source, все бесплатные):
#    nmap    : apt install nmap
#    httpx   : go install github.com/projectdiscovery/httpx/cmd/httpx@latest
#    whatweb : apt install whatweb   (уже есть в Kali Linux)
#    wafw00f : apt install wafw00f
#    jq      : apt install jq
# =============================================================================

if [ -z "$BASH_VERSION" ]; then exec bash "$0" "$@"; fi
set -uo pipefail

# ─── Цвета ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; MAGENTA='\033[0;35m'; NC='\033[0m'

info()    { echo -e "${CYAN}[*]${NC} $*"; }
success() { echo -e "${GREEN}[+]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
err()     { echo -e "${RED}[-]${NC} $*"; }
banner()  {
    local msg="$*"
    local pad=$(( 48 - ${#msg} ))
    local spaces; spaces=$(printf '%*s' "$pad" '')
    echo -e "\n${BOLD}${MAGENTA}╔══════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}${MAGENTA}║  ${msg}${spaces}║${NC}"
    echo -e "${BOLD}${MAGENTA}╚══════════════════════════════════════════════════╝${NC}\n"
}

has() { command -v "$1" &>/dev/null; }
lc()  { if [[ -f "$1" ]] && [[ -s "$1" ]]; then wc -l < "$1" | tr -d ' '; else echo 0; fi; }

# ─── Аргументы ───────────────────────────────────────────────────────────────
RECON_DIR="${1:-}"
if [[ -z "$RECON_DIR" ]] || [[ ! -d "$RECON_DIR" ]]; then
    echo "Использование: bash $0 <recon_output_dir>"
    echo "Пример:        bash $0 ./recon_astanait_edu_kz_20260315"
    exit 1
fi

# ─── Пути к файлам из recon.sh ───────────────────────────────────────────────
HTTPX_LIVE="$RECON_DIR/subdomains/httpx_live.txt"
RESOLVED_IPS="$RECON_DIR/dns/resolved_ips.txt"
RESOLVED_HOSTS="$RECON_DIR/dns/resolved_hosts.txt"
ALL_SUBS="$RECON_DIR/subdomains/all_subdomains.txt"

# ─── Директории для результатов ──────────────────────────────────────────────
ENRICH_DIR="$RECON_DIR/enrichment"
mkdir -p "$ENRICH_DIR"/{ports,wappalyzer}

PORTS_JSON="$ENRICH_DIR/ports/ports_results.json"
PORTS_MD="$ENRICH_DIR/ports/ports_results.md"
WAPPY_JSON="$ENRICH_DIR/wappalyzer/technologies.json"
WAPPY_MD="$ENRICH_DIR/wappalyzer/technologies.md"
FINAL_REPORT="$ENRICH_DIR/ENRICH_REPORT.md"

# ─── Проверка инструментов ───────────────────────────────────────────────────
banner "Проверка инструментов"
for t in nmap httpx whatweb wafw00f jq python3; do
    if has "$t"; then success "$t"
    else warn "$t — не найден"
    fi
done

info "Recon dir  : $RECON_DIR"
info "IP адресов : $(lc "$RESOLVED_IPS")"
info "Субдоменов : $(lc "$ALL_SUBS")"
info "HTTP хостов: $(lc "$HTTPX_LIVE")"

# ═══════════════════════════════════════════════════════════════════════════════
# МОДУЛЬ 1: СКАНИРОВАНИЕ ПОРТОВ
# ═══════════════════════════════════════════════════════════════════════════════
banner "1. Port Scan — nmap (top-1000)"

# Используем стандартный nmap top-1000

if [[ ! -s "$RESOLVED_IPS" ]]; then
    warn "Нет IP для сканирования портов: $RESOLVED_IPS"
else
    IP_COUNT=$(lc "$RESOLVED_IPS")
    info "Сканируем порты для $IP_COUNT IP..."

    PORTS_RAW="$ENRICH_DIR/ports/raw_scan.txt"
    > "$PORTS_RAW"

    if ! has nmap; then
        err "nmap не найден: apt install nmap"
    else
        info "Запуск nmap --top-ports 1000 для $IP_COUNT IP"
        nmap \
            -iL "$RESOLVED_IPS" \
            --top-ports 1000 \
            --open \
            -T4 \
            -n \
            --min-parallelism 100 \
            -oX "$ENRICH_DIR/ports/nmap_raw.xml" \
            -oG "$ENRICH_DIR/ports/nmap_raw.gnmap" \
            2>/dev/null || true
        success "nmap завершён"
    fi

    # ── Генерация ports_results.json ─────────────────────────────────────────
    info "Генерация ports_results.json..."
    python3 - \
        "$ENRICH_DIR/ports/naabu_raw.json" \
        "$ENRICH_DIR/ports/nmap_raw.xml" \
        "$ENRICH_DIR/ports/nmap_raw.gnmap" \
        "$RESOLVED_HOSTS" \
        "$PORTS_JSON" << 'PYEOF'
import sys, json, os, re
from collections import defaultdict

naabu_file  = sys.argv[1]
nmap_xml    = sys.argv[2]
nmap_gnmap  = sys.argv[3]
hosts_file  = sys.argv[4]
out_file    = sys.argv[5]

# Маппинг известных портов
PORT_NAMES = {
    21:"FTP", 22:"SSH", 23:"Telnet", 25:"SMTP", 53:"DNS",
    80:"HTTP", 110:"POP3", 111:"RPC", 135:"MSRPC", 139:"NetBIOS",
    143:"IMAP", 443:"HTTPS", 445:"SMB", 465:"SMTPS", 587:"SMTP",
    993:"IMAPS", 995:"POP3S", 1080:"SOCKS", 1433:"MSSQL", 1521:"Oracle",
    2181:"ZooKeeper", 2375:"Docker", 2376:"Docker-TLS", 3000:"Dev/Grafana",
    3306:"MySQL", 3389:"RDP", 4848:"GlassFish", 5000:"Dev/Flask",
    5432:"PostgreSQL", 5900:"VNC", 6379:"Redis", 7001:"WebLogic",
    8000:"HTTP-Alt", 8080:"HTTP-Proxy", 8081:"HTTP-Alt", 8082:"HTTP-Alt",
    8083:"HTTP-Alt", 8088:"HTTP-Alt", 8089:"Splunk", 8090:"HTTP-Alt",
    8443:"HTTPS-Alt", 8444:"HTTPS-Alt", 8500:"Consul", 8888:"Jupyter",
    9000:"SonarQube/PHP-FPM", 9090:"Prometheus", 9200:"Elasticsearch",
    9300:"Elasticsearch", 9443:"HTTPS-Alt", 10000:"Webmin",
    11211:"Memcached", 15672:"RabbitMQ", 27017:"MongoDB",
    28017:"MongoDB-Web", 50000:"SAP"
}

# IP → hostname маппинг из resolved_hosts
ip_to_hosts = defaultdict(list)
if os.path.exists(hosts_file):
    with open(hosts_file) as f:
        for line in f:
            line = line.strip()
            # Формат dnsx: hostname [A] [1.2.3.4]
            m = re.match(r'^(\S+)\s+\[A\]\s+\[([0-9.]+)\]', line)
            if m:
                hostname, ip = m.group(1), m.group(2)
                if hostname not in ip_to_hosts[ip]:
                    ip_to_hosts[ip].append(hostname)

results = defaultdict(lambda: {"ip": "", "hostnames": [], "open_ports": []})

# ── Парсинг naabu JSON (каждая строка — отдельный JSON объект) ───────────────
if os.path.exists(naabu_file) and os.path.getsize(naabu_file) > 0:
    with open(naabu_file) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                ip   = obj.get("ip", "")
                port = int(obj.get("port", 0))
                if not ip or not port:
                    continue
                if results[ip]["ip"] == "":
                    results[ip]["ip"] = ip
                    results[ip]["hostnames"] = ip_to_hosts.get(ip, [])
                entry = {
                    "port":    port,
                    "service": PORT_NAMES.get(port, "unknown"),
                    "state":   "open"
                }
                if entry not in results[ip]["open_ports"]:
                    results[ip]["open_ports"].append(entry)
            except Exception:
                continue

# ── Парсинг nmap grepable (.gnmap) как fallback ──────────────────────────────
if os.path.exists(nmap_gnmap) and os.path.getsize(nmap_gnmap) > 0:
    with open(nmap_gnmap) as f:
        for line in f:
            if not line.startswith("Host:"):
                continue
            # Host: 1.2.3.4 ()  Ports: 80/open/tcp//http///, 443/open/...
            m_ip = re.search(r'Host:\s+([0-9.]+)', line)
            m_ports = re.search(r'Ports:\s+(.+)', line)
            if not m_ip:
                continue
            ip = m_ip.group(1)
            if results[ip]["ip"] == "":
                results[ip]["ip"] = ip
                results[ip]["hostnames"] = ip_to_hosts.get(ip, [])
            if m_ports:
                for p in m_ports.group(1).split(","):
                    p = p.strip()
                    parts = p.split("/")
                    if len(parts) >= 2 and parts[1] == "open":
                        try:
                            port = int(parts[0])
                            entry = {
                                "port":    port,
                                "service": PORT_NAMES.get(port, parts[4] if len(parts) > 4 and parts[4] else "unknown"),
                                "state":   "open"
                            }
                            if entry not in results[ip]["open_ports"]:
                                results[ip]["open_ports"].append(entry)
                        except Exception:
                            continue

# Сортируем порты внутри каждого хоста
final = []
for ip, data in sorted(results.items()):
    data["open_ports"] = sorted(data["open_ports"], key=lambda x: x["port"])
    data["total_open"] = len(data["open_ports"])
    final.append(data)

with open(out_file, "w") as f:
    json.dump(final, f, indent=2, ensure_ascii=False)

print(f"JSON: {len(final)} хостов, всего открытых портов: {sum(h['total_open'] for h in final)}")
PYEOF

    success "JSON → $PORTS_JSON"

    # ── Генерация ports_results.md ────────────────────────────────────────────
    info "Генерация ports_results.md..."
    python3 - "$PORTS_JSON" "$PORTS_MD" << 'PYEOF'
import sys, json

json_file = sys.argv[1]
md_file   = sys.argv[2]

try:
    with open(json_file) as f:
        data = json.load(f)
except Exception as e:
    print(f"Ошибка чтения JSON: {e}")
    sys.exit(1)

total_hosts = len(data)
total_ports = sum(h.get("total_open", 0) for h in data)

# Подсчёт популярных портов
from collections import Counter
port_counter = Counter()
for h in data:
    for p in h.get("open_ports", []):
        port_counter[f"{p['port']}/{p['service']}"] += 1

lines = []
lines.append("# 🔌 Port Scan Results")
lines.append("")
lines.append(f"> **Дата:** {__import__('datetime').datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
lines.append("")
lines.append("---")
lines.append("")
lines.append("## 📊 Статистика")
lines.append("")
lines.append("| Метрика | Значение |")
lines.append("|---------|----------|")
lines.append(f"| Хостов с открытыми портами | {total_hosts} |")
lines.append(f"| Всего открытых портов | {total_ports} |")
lines.append("")
lines.append("## 🔝 Топ портов")
lines.append("")
lines.append("| Порт/Сервис | Кол-во хостов |")
lines.append("|------------|--------------|")
for port_svc, cnt in port_counter.most_common(20):
    lines.append(f"| {port_svc} | {cnt} |")
lines.append("")
lines.append("---")
lines.append("")
lines.append("## 🖥️ По хостам")
lines.append("")

for host in data:
    ip        = host.get("ip", "?")
    hostnames = host.get("hostnames", [])
    ports     = host.get("open_ports", [])
    total     = host.get("total_open", 0)

    lines.append(f"### `{ip}`")
    if hostnames:
        lines.append(f"**Hostnames:** {', '.join(hostnames)}")
    lines.append(f"**Открытых портов:** {total}")
    lines.append("")

    if ports:
        lines.append("| Порт | Сервис | Статус |")
        lines.append("|------|--------|--------|")
        for p in ports:
            lines.append(f"| {p['port']} | {p['service']} | ✅ open |")
    else:
        lines.append("*Открытых портов не найдено*")
    lines.append("")

with open(md_file, "w") as f:
    f.write("\n".join(lines))

print(f"MD: {total_hosts} хостов записано")
PYEOF

    success "MD → $PORTS_MD"
    info "Открытых хостов: $(python3 -c "import json; d=json.load(open('$PORTS_JSON')); print(len(d))" 2>/dev/null || echo 0)"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# МОДУЛЬ 2: ТЕХНОЛОГИИ — whatweb + httpx + wafw00f
# ═══════════════════════════════════════════════════════════════════════════════
banner "2. Технологии — whatweb / httpx / wafw00f"

# ── Собираем URL ──────────────────────────────────────────────────────────────
URLS_FILE="$ENRICH_DIR/wappalyzer/urls_to_scan.txt"
if [[ -s "$HTTPX_LIVE" ]]; then
    grep -oE 'https?://[^ ]+' "$HTTPX_LIVE" | sort -u > "$URLS_FILE" || true
elif [[ -s "$ALL_SUBS" ]]; then
    warn "httpx_live.txt не найден — строю URL из субдоменов"
    while IFS= read -r sub; do echo "https://$sub"; done < "$ALL_SUBS"         | sort -u > "$URLS_FILE"
fi

URL_COUNT=$(lc "$URLS_FILE")
if [[ "$URL_COUNT" -eq 0 ]]; then
    warn "Нет URL для сканирования"
else
    info "URL для сканирования: $URL_COUNT"

    RAW_WHATWEB="$ENRICH_DIR/wappalyzer/raw_whatweb.txt"
    RAW_HTTPX="$ENRICH_DIR/wappalyzer/raw_httpx.txt"
    RAW_WAFW00F="$ENRICH_DIR/wappalyzer/raw_wafw00f.txt"
    > "$RAW_WHATWEB"; > "$RAW_HTTPX"; > "$RAW_WAFW00F"

    # ── 2a. whatweb ───────────────────────────────────────────────────────────
    if has whatweb; then
        info "[1/3] whatweb -a 3"
        whatweb             -i "$URLS_FILE"             --log-brief="$RAW_WHATWEB"             -a 3             --no-errors             --colour=never             2>/dev/null || true
        success "whatweb → $(lc "$RAW_WHATWEB") строк"
    else
        warn "whatweb не найден: apt install whatweb"
    fi

    # ── 2b. httpx --tech-detect ───────────────────────────────────────────────
    if has httpx; then
        info "[2/3] httpx --tech-detect"
        httpx             -l "$URLS_FILE"             -tech-detect             -status-code             -title             -server             -silent             -no-color             -o "$RAW_HTTPX"             2>/dev/null || true
        success "httpx → $(lc "$RAW_HTTPX") строк"
    else
        warn "httpx не найден: go install github.com/projectdiscovery/httpx/cmd/httpx@latest"
    fi

    # ── 2c. wafw00f — WAF detection ───────────────────────────────────────────
    if has wafw00f; then
        info "[3/3] wafw00f — WAF detection"
        wafw00f             -i "$URLS_FILE"             -o "$RAW_WAFW00F"             2>/dev/null || true
        success "wafw00f → $(lc "$RAW_WAFW00F") строк"
    else
        warn "wafw00f не найден: apt install wafw00f"
    fi

    success "Сканирование завершено"


    # ── Генерация technologies.json ───────────────────────────────────────
    info "Генерация technologies.json..."
    python3 - "$RAW_WHATWEB" "$RAW_HTTPX" "$RAW_WAFW00F" "$WAPPY_JSON" << 'PYEOF'
import sys, json, re, datetime
from collections import defaultdict

raw_whatweb = sys.argv[1]
raw_httpx   = sys.argv[2]
raw_wafw00f = sys.argv[3]
json_file   = sys.argv[4]

CAT = {
    "Apache":"Web Server","Nginx":"Web Server","nginx":"Web Server",
    "IIS":"Web Server","LiteSpeed":"Web Server","OpenResty":"Web Server",
    "Tomcat":"Web Server","Gunicorn":"Web Server","Caddy":"Web Server",
    "PHP":"Programming Language","Python":"Programming Language",
    "Ruby":"Programming Language","Java":"Programming Language",
    "Node.js":"Programming Language","Perl":"Programming Language",
    "WordPress":"CMS","Drupal":"CMS","Joomla":"CMS","Bitrix":"CMS",
    "MODX":"CMS","1C-Bitrix":"CMS","Ghost":"CMS","Typo3":"CMS",
    "jQuery":"JavaScript Library","Lodash":"JavaScript Library",
    "React":"JavaScript Framework","Next.js":"JavaScript Framework",
    "Vue.js":"JavaScript Framework","Nuxt.js":"JavaScript Framework",
    "Angular":"JavaScript Framework","Svelte":"JavaScript Framework",
    "Bootstrap":"CSS Framework","Tailwind CSS":"CSS Framework",
    "Laravel":"Web Framework","Django":"Web Framework","Flask":"Web Framework",
    "Rails":"Web Framework","Spring":"Web Framework","Express":"Web Framework",
    "MySQL":"Database","PostgreSQL":"Database","MongoDB":"Database",
    "Redis":"Database","Elasticsearch":"Database","MariaDB":"Database",
    "Google Analytics":"Analytics","Google Tag Manager":"Analytics",
    "Yandex.Metrika":"Analytics","Matomo":"Analytics",
    "Cloudflare":"CDN/WAF","Varnish":"Cache","Amazon CloudFront":"CDN",
    "Let's Encrypt":"SSL/TLS","OpenSSL":"SSL/TLS",
}

SKIP = {
    "Country","IP","RedirectLocation","Title","UncommonHeaders",
    "X-Frame-Options","X-XSS-Protection","Strict-Transport-Security",
    "Content-Security-Policy","X-Content-Type-Options","Script",
    "HTML5","Open-Graph-Protocol","Email","Meta-Author","PoweredBy",
    "Cookies","Meta-Refresh","Frame","PasswordField","FormAction",
    "HTML","CSS",
}

def get_cat(name):
    return CAT.get(name, "Web Technology")

def parse_plugins(plugin_str):
    """Корректный парсинг строки плагинов whatweb с учётом вложенных скобок."""
    plugins = {}
    i, name_buf = 0, ""
    while i < len(plugin_str):
        ch = plugin_str[i]
        if ch == '[':
            depth, j = 1, i + 1
            while j < len(plugin_str) and depth > 0:
                if plugin_str[j] == '[': depth += 1
                elif plugin_str[j] == ']': depth -= 1
                j += 1
            value = plugin_str[i+1:j-1]
            key = name_buf.strip()
            if key:
                plugins[key] = value
            name_buf = ""
            i = j
            if i < len(plugin_str) and plugin_str[i] == ',': i += 1
            if i < len(plugin_str) and plugin_str[i] == ' ': i += 1
        elif plugin_str[i:i+2] == ', ':
            key = name_buf.strip()
            if key:
                plugins[key] = ""
            name_buf = ""
            i += 2
        else:
            name_buf += ch
            i += 1
    if name_buf.strip():
        plugins[name_buf.strip()] = ""
    return plugins

ansi = re.compile(r'\x1b\[[0-9;]*m')
results = {}

# ── Парсинг whatweb --log-brief ──────────────────────────────────────────────
try:
    with open(raw_whatweb, "r", errors="replace") as f:
        for line in f:
            line = ansi.sub("", line).strip()
            if not line or line.startswith("#"):
                continue
            m = re.match(r'(https?://\S+?)\s+\[(\d+)[^\]]*\]\s*(.*)', line)
            if not m:
                continue
            url, status, rest = m.group(1).rstrip("/"), m.group(2), m.group(3)
            if url not in results:
                results[url] = {"url":url,"status":status,"technologies":[],"waf":[]}

            for pname, pval in parse_plugins(rest).items():
                if pname in SKIP:
                    continue
                if pname == "HTTPServer" and pval:
                    server = pval.split("/")[0].strip()
                    ver = pval.split("/")[1].strip() if "/" in pval else None
                    results[url]["technologies"].append(
                        {"category":"Web Server","name":server,"version":ver,"source":"whatweb"})
                    continue
                if pname == "X-Powered-By" and pval:
                    name = pval.split("/")[0].strip()
                    ver  = pval.split("/")[1].strip() if "/" in pval else None
                    results[url]["technologies"].append(
                        {"category":get_cat(name),"name":name,"version":ver,"source":"whatweb"})
                    continue
                version = None
                if pval:
                    vm = re.search(r'\d+\.\d+[\.\d]*', pval)
                    if vm:
                        version = vm.group(0)
                results[url]["technologies"].append(
                    {"category":get_cat(pname),"name":pname,"version":version,"source":"whatweb"})
except FileNotFoundError:
    pass

# ── Парсинг httpx --tech-detect ──────────────────────────────────────────────
try:
    with open(raw_httpx, "r", errors="replace") as f:
        for line in f:
            line = ansi.sub("", line).strip()
            if not line:
                continue
            um = re.match(r'(https?://\S+)', line)
            if not um:
                continue
            url = um.group(1).rstrip("/")
            if url not in results:
                results[url] = {"url":url,"status":"?","technologies":[],"waf":[]}
            existing = {t["name"].lower() for t in results[url]["technologies"]}
            for b in re.findall(r'\[([^\]]+)\]', line):
                if re.match(r'^\d+$', b):
                    continue
                if len(b) > 80 and ',' not in b:
                    continue
                for tech in b.split(','):
                    tech = tech.strip()
                    if not tech or len(tech) < 2 or tech.lower() in existing:
                        continue
                    results[url]["technologies"].append(
                        {"category":get_cat(tech),"name":tech,"version":None,"source":"httpx"})
                    existing.add(tech.lower())
except FileNotFoundError:
    pass

# ── Парсинг wafw00f ───────────────────────────────────────────────────────────
try:
    with open(raw_wafw00f, "r", errors="replace") as f:
        for line in f:
            line = ansi.sub("", line).strip()
            m = re.search(r'(https?://\S+).*?behind\s+(.+?)(?:\s+WAF)?$', line, re.IGNORECASE)
            if m:
                url = m.group(1).rstrip("/")
                if url not in results:
                    results[url] = {"url":url,"status":"?","technologies":[],"waf":[]}
                results[url]["waf"].append(m.group(2).strip())
            m2 = re.search(r'(https?://\S+).*?No WAF', line, re.IGNORECASE)
            if m2:
                url = m2.group(1).rstrip("/")
                if url not in results:
                    results[url] = {"url":url,"status":"?","technologies":[],"waf":[]}
                if not results[url]["waf"]:
                    results[url]["waf"].append("None detected")
except FileNotFoundError:
    pass

final = list(results.values())
with open(json_file, "w") as f:
    json.dump(final, f, indent=2, ensure_ascii=False)

all_techs = set(t["name"] for h in final for t in h.get("technologies",[]))
print(f"JSON: {len(final)} хостов, {len(all_techs)} уникальных технологий")
PYEOF

    success "JSON → $WAPPY_JSON"

    # ── Генерация technologies.md ─────────────────────────────────────────
    info "Генерация technologies.md..."
    python3 - "$WAPPY_JSON" "$WAPPY_MD" << 'PYEOF'
import sys, json, datetime
from collections import Counter

data = json.load(open(sys.argv[1]))
md   = sys.argv[2]

all_techs = [t["name"]     for h in data for t in h.get("technologies",[])]
all_cats  = [t["category"] for h in data for t in h.get("technologies",[])]
all_wafs  = [w for h in data for w in h.get("waf",[]) if w != "None detected"]
tc = Counter(all_techs)
cc = Counter(all_cats)

L = []
L.append("# 🧰 Technologies Report")
L.append(f"\n> **Дата:** {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
L.append("> **Источники:** whatweb · httpx --tech-detect · wafw00f\n")
L.append("---\n")
L.append("## 📊 Статистика\n")
L.append("| Метрика | Значение |")
L.append("|---------|----------|")
L.append(f"| Хостов просканировано | {len(data)} |")
L.append(f"| Уникальных технологий | {len(set(all_techs))} |")
L.append(f"| Уникальных категорий  | {len(set(all_cats))} |")
L.append(f"| Хостов с WAF          | {len(all_wafs)} |\n")

if tc:
    L.append("## 🔝 Топ технологий\n")
    cat_for = {t["name"]:t["category"] for h in data for t in h.get("technologies",[])}
    L.append("| # | Технология | Категория | Хостов |")
    L.append("|---|-----------|-----------|--------|")
    for i,(tech,cnt) in enumerate(tc.most_common(30),1):
        L.append(f"| {i} | **{tech}** | {cat_for.get(tech,'—')} | {cnt} |")
    L.append("")

if cc:
    L.append("## 📂 По категориям\n")
    L.append("| Категория | Хостов |")
    L.append("|-----------|--------|")
    for cat,cnt in cc.most_common():
        L.append(f"| {cat} | {cnt} |")
    L.append("")

L.append("---\n")
L.append("## 🖥️ По хостам\n")

for host in sorted(data, key=lambda x: x.get("url","")):
    url    = host.get("url","?")
    status = host.get("status","?")
    techs  = host.get("technologies",[])
    wafs   = host.get("waf",[])
    icon   = "✅" if status=="200" else ("↪️" if status in ("301","302") else "⚠️")
    L.append(f"### {icon} `{url}` [{status}]\n")
    if wafs:
        L.append(f"> 🛡️ **WAF:** {', '.join(wafs)}\n")
    if techs:
        L.append("| Категория | Технология | Версия | Источник |")
        L.append("|-----------|-----------|--------|----------|")
        for t in sorted(techs, key=lambda x: x["category"]):
            ver = t.get("version") or "—"
            L.append(f"| {t['category']} | **{t['name']}** | {ver} | {t.get('source','—')} |")
    else:
        L.append("*Технологии не определены*")
    L.append("")

open(md,"w").write("\n".join(L))
print(f"MD: {len(data)} хостов записано")
PYEOF

    success "MD → $WAPPY_MD"

    # Сводка в терминал
    echo ""
    info "Топ-15 технологий:"
    python3 -c "
import json
from collections import Counter
d = json.load(open('$WAPPY_JSON'))
c = Counter(t['name'] for h in d for t in h.get('technologies',[]))
for i,(tech,cnt) in enumerate(c.most_common(15),1):
    print(f'  {i:>2}. {tech:<30} {cnt} хостов')
" 2>/dev/null || true
fi


# ═══════════════════════════════════════════════════════════════════════════════
# ФИНАЛЬНЫЙ ENRICH_REPORT.md
# ═══════════════════════════════════════════════════════════════════════════════
banner "3. Финальный отчёт"

{
echo "# 🔬 Enrich Report"
echo ""
echo "> **Дата:** $(date '+%Y-%m-%d %H:%M:%S')"
echo "> **Recon dir:** \`$RECON_DIR\`"
echo ""
echo "---"
echo ""

# ── Порты ────────────────────────────────────────────────────────────────────
echo "## 🔌 Port Scan"
echo ""
if [[ -s "$PORTS_JSON" ]]; then
    hosts_with_ports=$(python3 -c "import json; d=json.load(open('$PORTS_JSON')); print(len(d))" 2>/dev/null || echo 0)
    total_ports_found=$(python3 -c "import json; d=json.load(open('$PORTS_JSON')); print(sum(h.get('total_open',0) for h in d))" 2>/dev/null || echo 0)
    echo "| Метрика | Значение |"
    echo "|---------|----------|"
    echo "| Хостов с открытыми портами | $hosts_with_ports |"
    echo "| Всего открытых портов | $total_ports_found |"
    echo "| Детали | \`enrichment/ports/ports_results.md\` |"
    echo "| JSON | \`enrichment/ports/ports_results.json\` |"
    echo ""
    # Топ портов прямо в отчёт
    echo "### Топ открытых портов"
    echo ""
    python3 -c "
import json
from collections import Counter
d = json.load(open('$PORTS_JSON'))
c = Counter()
for h in d:
    for p in h.get('open_ports',[]):
        c[f\"{p['port']}/{p['service']}\"] += 1
print('| Порт/Сервис | Хостов |')
print('|------------|--------|')
for ps,cnt in c.most_common(15):
    print(f'| {ps} | {cnt} |')
" 2>/dev/null || true
else
    echo "> Нет данных (nmap не найден или нет IP)"
fi
echo ""
echo "---"
echo ""

# ── Wappalyzer ────────────────────────────────────────────────────────────────
echo "## 🧰 Wappalyzer"
echo ""
if [[ -s "$WAPPY_JSON" ]]; then
    python3 -c "
import json
from collections import Counter
d = json.load(open('$WAPPY_JSON'))
all_t = [t['name'] for h in d for t in h.get('technologies',[])]
all_c = [t['category'] for h in d for t in h.get('technologies',[])]
print('| Метрика | Значение |')
print('|---------|----------|')
print(f'| Хостов просканировано | {len(d)} |')
print(f'| Уникальных технологий | {len(set(all_t))} |')
print(f'| Уникальных категорий  | {len(set(all_c))} |')
print(f'| Детали | \`enrichment/wappalyzer/technologies.md\` |')
print(f'| JSON   | \`enrichment/wappalyzer/technologies.json\` |')
" 2>/dev/null || true
    echo ""
    echo "### Топ технологий"
    echo ""
    python3 -c "
import json
from collections import Counter
d = json.load(open('$WAPPY_JSON'))
c = Counter(t['name'] for h in d for t in h.get('technologies',[]))
print('| # | Технология | Хостов |')
print('|---|-----------|--------|')
for i,(tech,cnt) in enumerate(c.most_common(20),1):
    print(f'| {i} | {tech} | {cnt} |')
" 2>/dev/null || true
else
    echo "> Нет данных (инструменты не установлены или нет живых хостов)"
fi
echo ""
echo "---"
echo ""

# ── Файлы ─────────────────────────────────────────────────────────────────────
echo "## 📁 Файлы"
echo ""
echo '```'
find "$ENRICH_DIR" -type f | sort | while read -r f; do
    lines=$(wc -l < "$f" 2>/dev/null || echo 0)
    printf "%-6s lines  %s\n" "$lines" "${f#$RECON_DIR/}"
done
echo '```'

} > "$FINAL_REPORT"

success "Отчёт → $FINAL_REPORT"

# ─── Итог ─────────────────────────────────────────────────────────────────────
banner "Готово"
echo -e "${BOLD}Файлы:${NC}"
echo -e "  ${GREEN}Порты JSON     :${NC} $PORTS_JSON"
echo -e "  ${GREEN}Порты MD       :${NC} $PORTS_MD"
echo -e "  ${GREEN}Технологии JSON:${NC} $WAPPY_JSON"
echo -e "  ${GREEN}Технологии MD  :${NC} $WAPPY_MD"
echo -e "  ${GREEN}Общий отчёт    :${NC} $FINAL_REPORT"
echo ""
echo -e "${BOLD}Просмотр:${NC}"
echo "  cat $FINAL_REPORT"
echo "  cat $PORTS_MD"
echo "  cat $WAPPY_MD"
