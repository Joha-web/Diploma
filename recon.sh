#!/usr/bin/env bash
# =============================================================================
#  recon.sh — Максимальная разведка по домену/IP (без сканирования портов)
#  Запуск: bash recon.sh <domain|ip> [output_dir]
# =============================================================================

if [ -z "$BASH_VERSION" ]; then exec bash "$0" "$@"; fi

# ВАЖНО: НЕ используем set -e, чтобы скрипт не падал на ошибках инструментов
set -uo pipefail

# ─── Цвета ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; MAGENTA='\033[0;35m'; NC='\033[0m'

info()    { echo -e "${CYAN}[*]${NC} $*"; }
success() { echo -e "${GREEN}[+]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
banner()  {
    local msg="$*"
    local len=${#msg}
    local pad=$(( 48 - len ))
    local spaces=""
    local i=0
    while [[ $i -lt $pad ]]; do spaces="${spaces} "; i=$(( i + 1 )); done
    echo -e "\n${BOLD}${MAGENTA}╔══════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}${MAGENTA}║  ${msg}${spaces}║${NC}"
    echo -e "${BOLD}${MAGENTA}╚══════════════════════════════════════════════════╝${NC}\n"
}

# ─── Аргументы ───────────────────────────────────────────────────────────────
TARGET="${1:-}"
if [[ -z "$TARGET" ]]; then
    echo "Использование: bash $0 <domain|ip> [output_dir]"
    exit 1
fi

OUTPUT_DIR="${2:-./recon_$(echo "$TARGET" | tr './' '__')_$(date +%Y%m%d_%H%M%S)}"
mkdir -p "$OUTPUT_DIR"/{subdomains,dns,urls,passive}

DOMAIN="$TARGET"
IS_IP=false
RDNS=""

if [[ "$TARGET" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    IS_IP=true
    info "Цель — IP-адрес: $TARGET"
    RDNS=$(dig +short -x "$TARGET" 2>/dev/null | sed 's/\.$//' | head -1 || true)
    if [[ -n "$RDNS" ]]; then
        success "Reverse DNS: $RDNS"
        DOMAIN="$RDNS"
        echo "$RDNS" > "$OUTPUT_DIR/dns/reverse_dns.txt"
    else
        warn "Reverse DNS не найден"
        DOMAIN=""
    fi
fi

MASTER="$OUTPUT_DIR/subdomains/all_subdomains.txt"
touch "$MASTER"

# ─── Утилиты ─────────────────────────────────────────────────────────────────
has() { command -v "$1" &>/dev/null; }

# Безопасный счётчик строк
lc() {
    if [[ -f "$1" ]] && [[ -s "$1" ]]; then
        wc -l < "$1" | tr -d ' '
    else
        echo 0
    fi
}

# Безопасный вывод файла
show_file() {
    if [[ -f "$1" ]] && [[ -s "$1" ]]; then cat "$1"
    else echo "(нет данных)"
    fi
}

# Мерж в мастер список — ТОЛЬКО субдомены целевого домена
merge() {
    local src="$1"
    if [[ -f "$src" ]] && [[ -s "$src" ]] && [[ -n "$DOMAIN" ]]; then
        local ESC_D="${DOMAIN//./\.}"
        grep -iE "(^|\.)${ESC_D}$" "$src" 2>/dev/null             | grep -v "^$" >> "$MASTER" || true
        sort -u "$MASTER" -o "$MASTER" || true
    fi
}



# ─── Проверка инструментов ────────────────────────────────────────────────────
banner "Проверка инструментов"
for t in subfinder amass assetfinder dnsx httpx waybackurls gau curl jq dig whois; do
    if has "$t"; then success "$t"
    else warn "$t — не найден (шаг пропущен)"
    fi
done

# ══════════════════════════════════════════════════════════════════════════════
# 1. WHOIS
# ══════════════════════════════════════════════════════════════════════════════
banner "1. WHOIS"

if has whois && [[ -n "$DOMAIN" ]]; then
    whois "$DOMAIN" > "$OUTPUT_DIR/passive/whois_full.txt" 2>/dev/null || true
    {
        echo "=== Registrar / Organization ==="
        grep -iE "^(registrar|org|organisation|organization|владелец|организация):" \
            "$OUTPUT_DIR/passive/whois_full.txt" 2>/dev/null | head -5 || true
        echo ""
        echo "=== Dates ==="
        grep -iE "(creat|expir|updat|registr).*date" \
            "$OUTPUT_DIR/passive/whois_full.txt" 2>/dev/null | head -6 || true
        echo ""
        echo "=== Name Servers ==="
        grep -iE "^name.?server" \
            "$OUTPUT_DIR/passive/whois_full.txt" 2>/dev/null | head -10 || true
        echo ""
        echo "=== Emails ==="
        grep -oE "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}" \
            "$OUTPUT_DIR/passive/whois_full.txt" 2>/dev/null | sort -u || true
    } > "$OUTPUT_DIR/passive/whois_summary.txt"
    success "WHOIS собран"
fi

# ══════════════════════════════════════════════════════════════════════════════
# 2. DNS ЗАПИСИ
# ══════════════════════════════════════════════════════════════════════════════
if [[ -n "$DOMAIN" ]]; then
    banner "2. DNS Записи"
    {
        for type in A AAAA MX NS TXT CNAME SOA; do
            echo "=== $type ==="
            dig +short "$type" "$DOMAIN" 2>/dev/null || true
            echo ""
        done
    } > "$OUTPUT_DIR/dns/dns_records.txt"
    success "DNS записи сохранены"

    info "Zone Transfer (AXFR)"
    while IFS= read -r ns; do
        ns="${ns%.}"
        [[ -z "$ns" ]] && continue
        result=$(dig AXFR "@$ns" "$DOMAIN" 2>/dev/null || true)
        if echo "$result" | grep -qiE "IN[[:space:]]+A[[:space:]]"; then
            echo "$result" >> "$OUTPUT_DIR/dns/zone_transfer.txt"
            success "AXFR успешен через $ns!"
        fi
    done < <(dig +short NS "$DOMAIN" 2>/dev/null || true)
fi

# ══════════════════════════════════════════════════════════════════════════════
# 3. ПАССИВНЫЕ ИСТОЧНИКИ СУБДОМЕНОВ
# ══════════════════════════════════════════════════════════════════════════════
if [[ -n "$DOMAIN" ]]; then
    banner "3. Пассивные источники субдоменов"
    ESC="${DOMAIN//./\\.}"

    # crt.sh
    info "crt.sh"
    curl -s --max-time 30 "https://crt.sh/?q=%.${DOMAIN}&output=json" 2>/dev/null \
        | jq -r '.[].name_value' 2>/dev/null \
        | tr ',' '\n' | sed 's/^\*\.//' \
        | grep -E "\.?${ESC}$" | sort -u \
        > "$OUTPUT_DIR/subdomains/crtsh.txt" || true
    merge "$OUTPUT_DIR/subdomains/crtsh.txt"
    success "crt.sh → $(lc "$OUTPUT_DIR/subdomains/crtsh.txt") субдоменов"

    # HackerTarget
    info "HackerTarget"
    curl -s --max-time 30 "https://api.hackertarget.com/hostsearch/?q=${DOMAIN}" 2>/dev/null \
        | cut -d',' -f1 | grep -E "\.?${ESC}$" | sort -u \
        > "$OUTPUT_DIR/subdomains/hackertarget.txt" || true
    merge "$OUTPUT_DIR/subdomains/hackertarget.txt"
    success "HackerTarget → $(lc "$OUTPUT_DIR/subdomains/hackertarget.txt") субдоменов"

    # AlienVault OTX
    info "AlienVault OTX"
    curl -s --max-time 30 \
        "https://otx.alienvault.com/api/v1/indicators/domain/${DOMAIN}/passive_dns" 2>/dev/null \
        | jq -r '.passive_dns[].hostname' 2>/dev/null \
        | grep -E "\.?${ESC}$" | sort -u \
        > "$OUTPUT_DIR/subdomains/alienvault.txt" || true
    merge "$OUTPUT_DIR/subdomains/alienvault.txt"
    success "AlienVault → $(lc "$OUTPUT_DIR/subdomains/alienvault.txt") субдоменов"

    # RapidDNS
    info "RapidDNS"
    curl -s --max-time 30 "https://rapiddns.io/subdomain/${DOMAIN}?full=1" 2>/dev/null \
        | grep -oP "[a-zA-Z0-9._-]+\.${ESC}" | sort -u \
        > "$OUTPUT_DIR/subdomains/rapiddns.txt" || true
    merge "$OUTPUT_DIR/subdomains/rapiddns.txt"
    success "RapidDNS → $(lc "$OUTPUT_DIR/subdomains/rapiddns.txt") субдоменов"

    # Wayback CDX
    info "Wayback Machine CDX"
    curl -s --max-time 30 \
        "http://web.archive.org/cdx/search/cdx?url=*.${DOMAIN}&output=text&fl=original&collapse=urlkey&limit=5000" \
        2>/dev/null \
        | grep -oP "[a-zA-Z0-9._-]+\.${ESC}" | sort -u \
        > "$OUTPUT_DIR/subdomains/wayback_cdx.txt" || true
    merge "$OUTPUT_DIR/subdomains/wayback_cdx.txt"
    success "Wayback CDX → $(lc "$OUTPUT_DIR/subdomains/wayback_cdx.txt") субдоменов"

    # ThreatMiner
    info "ThreatMiner"
    curl -s --max-time 30 \
        "https://api.threatminer.org/v2/domain.php?q=${DOMAIN}&rt=5" 2>/dev/null \
        | jq -r '.results[]' 2>/dev/null \
        | grep -E "\.?${ESC}$" | sort -u \
        > "$OUTPUT_DIR/subdomains/threatminer.txt" || true
    merge "$OUTPUT_DIR/subdomains/threatminer.txt"
    success "ThreatMiner → $(lc "$OUTPUT_DIR/subdomains/threatminer.txt") субдоменов"

    # subfinder
    if has subfinder; then
        info "subfinder"
        subfinder -d "$DOMAIN" -silent -all \
            -o "$OUTPUT_DIR/subdomains/subfinder.txt" 2>/dev/null || true
        merge "$OUTPUT_DIR/subdomains/subfinder.txt"
        success "subfinder → $(lc "$OUTPUT_DIR/subdomains/subfinder.txt") субдоменов"
    fi

    # assetfinder
    if has assetfinder; then
        info "assetfinder"
        assetfinder --subs-only "$DOMAIN" 2>/dev/null \
            | grep -E "\.?${ESC}$" | sort -u \
            > "$OUTPUT_DIR/subdomains/assetfinder.txt" || true
        merge "$OUTPUT_DIR/subdomains/assetfinder.txt"
        success "assetfinder → $(lc "$OUTPUT_DIR/subdomains/assetfinder.txt") субдоменов"
    fi

    # amass (с timeout чтобы не ждать вечно)
    if has amass; then
        info "amass (passive, timeout 3 мин)"
        timeout 180 amass enum -passive -d "$DOMAIN" \
            -o "$OUTPUT_DIR/subdomains/amass.txt" 2>/dev/null || true
        merge "$OUTPUT_DIR/subdomains/amass.txt"
        success "amass → $(lc "$OUTPUT_DIR/subdomains/amass.txt") субдоменов"
    fi

    success "Итого уникальных субдоменов: $(lc "$MASTER")"
fi

# ══════════════════════════════════════════════════════════════════════════════
# 4. DNS РЕЗОЛЮЦИЯ
# ══════════════════════════════════════════════════════════════════════════════
if [[ -n "$DOMAIN" ]] && [[ -s "$MASTER" ]]; then
    banner "4. DNS Резолюция ($(lc "$MASTER") хостов)"

    if has dnsx; then
        dnsx -l "$MASTER" -a -cname -resp \
            -threads 100 -silent -no-color 2>/dev/null \
            | sed 's/\x1b\[[0-9;]*m//g' \
            > "$OUTPUT_DIR/dns/resolved_hosts.txt" || true
        grep -oE "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" \
            "$OUTPUT_DIR/dns/resolved_hosts.txt" 2>/dev/null \
            | sort -u > "$OUTPUT_DIR/dns/resolved_ips.txt" || true
        success "Живых хостов: $(lc "$OUTPUT_DIR/dns/resolved_hosts.txt")"
    else
        info "dnsx не найден — резолюция через dig (медленно)"
        while IFS= read -r sub; do
            ip=$(dig +short A "$sub" 2>/dev/null | grep -vE "^\s*$|SERVFAIL" | head -1 || true)
            if [[ -n "$ip" ]]; then
                echo "$sub [$ip]" >> "$OUTPUT_DIR/dns/resolved_hosts.txt"
                echo "$ip" >> "$OUTPUT_DIR/dns/resolved_ips.txt"
            fi
        done < "$MASTER"
        [[ -f "$OUTPUT_DIR/dns/resolved_ips.txt" ]] && \
            sort -u "$OUTPUT_DIR/dns/resolved_ips.txt" -o "$OUTPUT_DIR/dns/resolved_ips.txt" || true
        success "Резолюция завершена: $(lc "$OUTPUT_DIR/dns/resolved_hosts.txt") живых хостов"
    fi
fi

# ══════════════════════════════════════════════════════════════════════════════
# 6.# 6. HTTP ПРОВЕРКА
# ══════════════════════════════════════════════════════════════════════════════
if [[ -n "$DOMAIN" ]] && [[ -s "$MASTER" ]]; then
    banner "6. HTTP/HTTPS хосты"

    if has httpx; then
        info "httpx → $(lc "$MASTER") хостов"
        httpx -l "$MASTER" \
            -title -status-code -tech-detect \
            -follow-redirects -threads 50 -silent \
            -o "$OUTPUT_DIR/subdomains/httpx_live.txt" 2>/dev/null || true
        success "Живых HTTP хостов: $(lc "$OUTPUT_DIR/subdomains/httpx_live.txt")"

        for code in 200 301 302 401 403 500; do
            grep "\[$code\]" "$OUTPUT_DIR/subdomains/httpx_live.txt" \
                2>/dev/null > "$OUTPUT_DIR/subdomains/http_${code}.txt" || true
        done
    fi
fi

# ══════════════════════════════════════════════════════════════════════════════
# 7. URL РАЗВЕДКА
# ══════════════════════════════════════════════════════════════════════════════
if [[ -n "$DOMAIN" ]]; then
    banner "7. URL / Endpoint разведка"

    if has waybackurls; then
        info "waybackurls"
        echo "$DOMAIN" | waybackurls 2>/dev/null \
            | sort -u > "$OUTPUT_DIR/urls/waybackurls.txt" || true
        success "waybackurls → $(lc "$OUTPUT_DIR/urls/waybackurls.txt") URL"
    fi

    if has gau; then
        info "gau"
        gau --subs "$DOMAIN" 2>/dev/null \
            | sort -u > "$OUTPUT_DIR/urls/gau.txt" || true
        success "gau → $(lc "$OUTPUT_DIR/urls/gau.txt") URL"
    fi

    cat "$OUTPUT_DIR/urls/"*.txt 2>/dev/null \
        | grep -v "^$" | sort -u > "$OUTPUT_DIR/urls/all_urls.txt" || true

    if [[ -s "$OUTPUT_DIR/urls/all_urls.txt" ]]; then
        grep -iE "\.(php|asp|aspx|jsp|json|xml|yaml|yml|env|git|bak|sql|db|conf|config|log|backup|zip|tar\.gz|key|pem)(\?.*)?$" \
            "$OUTPUT_DIR/urls/all_urls.txt" | sort -u \
            > "$OUTPUT_DIR/urls/interesting_files.txt" || true

        grep -iE "/(admin|login|logout|dashboard|api/|v[0-9]/|graphql|swagger|redoc|upload|backup|config|secret|token|oauth|auth|reset|debug|console|actuator|health|metrics)" \
            "$OUTPUT_DIR/urls/all_urls.txt" | sort -u \
            > "$OUTPUT_DIR/urls/interesting_endpoints.txt" || true

        grep -E "\?.*=" "$OUTPUT_DIR/urls/all_urls.txt" | sort -u \
            > "$OUTPUT_DIR/urls/urls_with_params.txt" || true

        success "Всего URL: $(lc "$OUTPUT_DIR/urls/all_urls.txt")"
        success "Интересных файлов: $(lc "$OUTPUT_DIR/urls/interesting_files.txt")"
        success "Интересных endpoint'ов: $(lc "$OUTPUT_DIR/urls/interesting_endpoints.txt")"
        success "URL с параметрами: $(lc "$OUTPUT_DIR/urls/urls_with_params.txt")"
    fi
fi

# ══════════════════════════════════════════════════════════════════════════════
# 8. ГЕНЕРАЦИЯ ОТЧЁТА
# ══════════════════════════════════════════════════════════════════════════════
banner "8. Генерация отчёта"

REPORT="$OUTPUT_DIR/REPORT.md"

{
echo "# 🔍 Recon Report: \`${TARGET}\`"
echo ""
echo "> **Дата:** $(date '+%Y-%m-%d %H:%M:%S')"
echo ""
echo "---"
echo ""
echo "## 🎯 Цель"
echo ""
echo "| Параметр | Значение |"
echo "|----------|----------|"
echo "| Target | \`${TARGET}\` |"
if [[ "$IS_IP" == true ]]; then
    echo "| Тип | IP-адрес |"
else
    echo "| Тип | Домен |"
fi
if [[ -n "$RDNS" ]]; then
    echo "| Reverse DNS | \`${RDNS}\` |"
fi
echo ""
echo "---"
echo ""

# ── Статистика субдоменов ────────────────────────────────────────────────────
echo "## 📊 Статистика по источникам"
echo ""
echo "| Источник | Найдено |"
echo "|----------|---------|"
for f in \
    "$OUTPUT_DIR/subdomains/crtsh.txt" \
    "$OUTPUT_DIR/subdomains/hackertarget.txt" \
    "$OUTPUT_DIR/subdomains/alienvault.txt" \
    "$OUTPUT_DIR/subdomains/rapiddns.txt" \
    "$OUTPUT_DIR/subdomains/wayback_cdx.txt" \
    "$OUTPUT_DIR/subdomains/threatminer.txt" \
    "$OUTPUT_DIR/subdomains/subfinder.txt" \
    "$OUTPUT_DIR/subdomains/assetfinder.txt" \
    "$OUTPUT_DIR/subdomains/amass.txt"; do
    [[ -f "$f" ]] || continue
    fname=$(basename "$f" .txt)
    cnt=$(lc "$f")
    [[ "$cnt" -gt 0 ]] && echo "| ${fname} | ${cnt} |"
done
echo "| **ИТОГО уникальных** | **$(lc "$MASTER")** |"
echo ""
echo "---"
echo ""

# ── Все субдомены ────────────────────────────────────────────────────────────
TOTAL=$(lc "$MASTER")
echo "## 🌐 Все субдомены (${TOTAL})"
echo ""
echo '```'
show_file "$MASTER"
echo '```'
echo ""
echo "---"
echo ""

# ── DNS записи ───────────────────────────────────────────────────────────────
echo "## 🔴 DNS Записи"
echo ""
echo '```'
show_file "$OUTPUT_DIR/dns/dns_records.txt"
echo '```'
echo ""
echo "---"
echo ""

# ── Живые хосты ──────────────────────────────────────────────────────────────
echo "## ✅ Живые хосты после резолюции ($(lc "$OUTPUT_DIR/dns/resolved_hosts.txt"))"
echo ""
echo '```'
show_file "$OUTPUT_DIR/dns/resolved_hosts.txt"
echo '```'
echo ""
echo "---"
echo ""

# ── IP адреса ────────────────────────────────────────────────────────────────
echo "## 🌍 Уникальные IP адреса ($(lc "$OUTPUT_DIR/dns/resolved_ips.txt"))"
echo ""
echo '```'
show_file "$OUTPUT_DIR/dns/resolved_ips.txt"
echo '```'
echo ""
echo "---"
echo ""



# ── HTTP хосты ───────────────────────────────────────────────────────────────
if [[ -s "$OUTPUT_DIR/subdomains/httpx_live.txt" ]]; then
    echo "## 🌐 Живые HTTP/HTTPS хосты ($(lc "$OUTPUT_DIR/subdomains/httpx_live.txt"))"
    echo ""
    echo '```'
    show_file "$OUTPUT_DIR/subdomains/httpx_live.txt"
    echo '```'
    echo ""

    for code in 200 301 302 401 403 500; do
        f="$OUTPUT_DIR/subdomains/http_${code}.txt"
        cnt=$(lc "$f")
        if [[ "$cnt" -gt 0 ]]; then
            echo "### HTTP ${code} (${cnt} хостов)"
            echo ""
            echo '```'
            cat "$f"
            echo '```'
            echo ""
        fi
    done

    echo "---"
    echo ""
fi

# ── WHOIS ────────────────────────────────────────────────────────────────────
if [[ -s "$OUTPUT_DIR/passive/whois_summary.txt" ]]; then
    echo "## 📋 WHOIS"
    echo ""
    echo '```'
    show_file "$OUTPUT_DIR/passive/whois_summary.txt"
    echo '```'
    echo ""
    echo "---"
    echo ""
fi

# ── Интересные endpoint'ы ─────────────────────────────────────────────────────
if [[ -s "$OUTPUT_DIR/urls/interesting_endpoints.txt" ]]; then
    echo "## 🎯 Интересные Endpoint'ы ($(lc "$OUTPUT_DIR/urls/interesting_endpoints.txt"))"
    echo ""
    echo '```'
    head -100 "$OUTPUT_DIR/urls/interesting_endpoints.txt"
    echo '```'
    echo ""
    echo "---"
    echo ""
fi

# ── Интересные файлы ─────────────────────────────────────────────────────────
if [[ -s "$OUTPUT_DIR/urls/interesting_files.txt" ]]; then
    echo "## 📁 Интересные файлы ($(lc "$OUTPUT_DIR/urls/interesting_files.txt"))"
    echo ""
    echo '```'
    head -100 "$OUTPUT_DIR/urls/interesting_files.txt"
    echo '```'
    echo ""
    echo "---"
    echo ""
fi

# ── URL с параметрами ─────────────────────────────────────────────────────────
if [[ -s "$OUTPUT_DIR/urls/urls_with_params.txt" ]]; then
    echo "## 🔗 URL с параметрами — потенциал XSS/SQLi ($(lc "$OUTPUT_DIR/urls/urls_with_params.txt"))"
    echo ""
    echo '```'
    head -100 "$OUTPUT_DIR/urls/urls_with_params.txt"
    echo '```'
    echo ""
    echo "---"
    echo ""
fi

# ── Следующие шаги ────────────────────────────────────────────────────────────
echo "## ⚡ Следующие шаги"
echo ""
echo "| Приоритет | Действие |"
echo "|-----------|----------|"
echo "| 🔴 Высокий | Сканирование портов живых IP (nmap/masscan) |"
echo "| 🔴 Высокий | Ручная проверка admin/login панелей |"
echo "| 🟡 Средний | Fuzzing endpoint'ов (ffuf/feroxbuster) |"
echo "| 🟡 Средний | Проверка .env, .git, backup файлов |"
echo "| 🟢 Низкий  | Полный краулинг живых хостов (katana) |"
echo "| 🟢 Низкий  | Скриншоты всех HTTP хостов (gowitness) |"

} > "$REPORT"

success "Отчёт сгенерирован → $REPORT"

# ══════════════════════════════════════════════════════════════════════════════
# ИТОГ
# ══════════════════════════════════════════════════════════════════════════════
banner "Разведка завершена"

echo -e "${BOLD}📁 Результаты: ${CYAN}${OUTPUT_DIR}${NC}"
echo ""
echo -e "  ${GREEN}Субдоменов всего:${NC}  $(lc "$MASTER")"
echo -e "  ${GREEN}Живых хостов:${NC}     $(lc "$OUTPUT_DIR/dns/resolved_hosts.txt")"
echo -e "  ${GREEN}HTTP хостов:${NC}      $(lc "$OUTPUT_DIR/subdomains/httpx_live.txt" 2>/dev/null || echo 0)"
echo -e "  ${GREEN}Уникальных IP:${NC}    $(lc "$OUTPUT_DIR/dns/resolved_ips.txt")"
echo -e "  ${GREEN}Всего URL:${NC}        $(lc "$OUTPUT_DIR/urls/all_urls.txt" 2>/dev/null || echo 0)"
echo ""
echo -e "${BOLD}Просмотр отчёта:${NC}"
echo "  cat $REPORT"
echo "  cat $OUTPUT_DIR/subdomains/all_subdomains.txt"
echo "  cat $OUTPUT_DIR/subdomains/httpx_live.txt"
