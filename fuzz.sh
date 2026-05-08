#!/usr/bin/env bash
# =============================================================================
#  fuzz.sh — Поиск endpoints на HTTP/HTTPS хостах
#  Модули:
#    1. Crawling    — katana (активный краулер)
#    2. Bruteforce  — feroxbuster (рекурсивный fuzzing директорий)
#    3. Fuzzing     — ffuf (параметры, файлы, виртуальные хосты)
#    4. JS Mining   — поиск endpoint'ов в JS-файлах
#    5. Отчёт       — FUZZ_REPORT.md
#
#  Запуск:
#    bash fuzz.sh <recon_output_dir> [wordlist_dir]
#
#  Примеры:
#    bash fuzz.sh ./recon_example_com_20260101
#    bash fuzz.sh ./recon_example_com_20260101 /usr/share/wordlists
#
#  Зависимости (open-source, все бесплатные):
#    katana       : go install github.com/projectdiscovery/katana/cmd/katana@latest
#    feroxbuster  : apt install feroxbuster  /  cargo install feroxbuster
#    ffuf         : go install github.com/ffuf/ffuf/v2@latest
#    curl         : apt install curl
#    jq           : apt install jq
#    python3      : apt install python3
#
#  Wordlists (рекомендуемые):
#    SecLists     : git clone https://github.com/danielmiessler/SecLists /opt/SecLists
#    dirb common  : /usr/share/dirb/wordlists/common.txt  (apt install dirb)
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
show_file() {
    if [[ -f "$1" ]] && [[ -s "$1" ]]; then cat "$1"
    else echo "(нет данных)"
    fi
}

# ─── Аргументы ───────────────────────────────────────────────────────────────
RECON_DIR="${1:-}"
if [[ -z "$RECON_DIR" ]] || [[ ! -d "$RECON_DIR" ]]; then
    echo "Использование: bash $0 <recon_output_dir> [wordlist_dir]"
    echo "Пример:        bash $0 ./recon_example_com_20260101"
    exit 1
fi

WORDLIST_DIR="${2:-}"

# ─── Пути к файлам из recon.sh ───────────────────────────────────────────────
HTTPX_LIVE="$RECON_DIR/subdomains/httpx_live.txt"

if [[ ! -s "$HTTPX_LIVE" ]]; then
    err "Не найден файл живых HTTP хостов: $HTTPX_LIVE"
    err "Убедись, что recon.sh был запущен с httpx"
    exit 1
fi

# ─── Директории для результатов ──────────────────────────────────────────────
FUZZ_DIR="$RECON_DIR/fuzzing"
mkdir -p "$FUZZ_DIR"/{crawl,ferox,ffuf,js_mining,merged}

FUZZ_REPORT="$FUZZ_DIR/FUZZ_REPORT.md"

# ─── Поиск wordlist'ов ────────────────────────────────────────────────────────
# Приоритет: аргумент > SecLists > dirb > встроенный мини-список
find_wordlist() {
    local name="$1"
    # Если передан явный каталог — ищем там
    if [[ -n "$WORDLIST_DIR" ]]; then
        local found; found=$(find "$WORDLIST_DIR" -name "$name" 2>/dev/null | head -1)
        [[ -n "$found" ]] && echo "$found" && return
    fi
    # SecLists
    local seclists_dirs=("/opt/SecLists" "/usr/share/seclists" "$HOME/SecLists")
    for d in "${seclists_dirs[@]}"; do
        local found; found=$(find "$d" -name "$name" 2>/dev/null | head -1)
        [[ -n "$found" ]] && echo "$found" && return
    done
    # dirb
    local dirb_common="/usr/share/dirb/wordlists/common.txt"
    if [[ "$name" == *"common"* ]] && [[ -f "$dirb_common" ]]; then
        echo "$dirb_common" && return
    fi
    echo ""
}

# Основной wordlist для директорий
WL_DIRS=$(find_wordlist "directory-list-2.3-medium.txt")
[[ -z "$WL_DIRS" ]] && WL_DIRS=$(find_wordlist "common.txt")

# Wordlist для файлов
WL_FILES=$(find_wordlist "raft-medium-files.txt")
[[ -z "$WL_FILES" ]] && WL_FILES="$WL_DIRS"

# Wordlist для параметров
WL_PARAMS=$(find_wordlist "burp-parameter-names.txt")
[[ -z "$WL_PARAMS" ]] && WL_PARAMS=$(find_wordlist "params.txt")

# Если ничего не нашли — создаём встроенный мини-список
BUILTIN_WL="$FUZZ_DIR/builtin_wordlist.txt"
if [[ -z "$WL_DIRS" ]]; then
    warn "Wordlist не найден — создаю встроенный мини-список (800 слов)"
    cat > "$BUILTIN_WL" << 'WORDLIST'
admin
administrator
api
api/v1
api/v2
api/v3
app
assets
auth
backup
backups
bin
blog
cache
cgi-bin
cms
config
console
dashboard
data
database
db
debug
deploy
dev
docs
download
downloads
env
error
errors
files
forum
git
health
help
hidden
images
img
include
includes
info
js
json
lib
library
login
logout
manage
media
metrics
monitor
old
panel
php
phpinfo
phpinfo.php
phpMyAdmin
php-fpm
private
prometheus
public
queue
register
robots.txt
scripts
secret
secrets
server
setup
src
static
status
swagger
swagger.json
swagger-ui
swagger-ui.html
test
tests
tmp
tools
upload
uploads
user
users
vendor
web
webadmin
webpack
wp-admin
wp-content
wp-login.php
.env
.git
.git/HEAD
.htaccess
.htpasswd
.well-known
sitemap.xml
crossdomain.xml
README.md
CHANGELOG.md
LICENSE
package.json
composer.json
Gemfile
Makefile
Dockerfile
docker-compose.yml
.DS_Store
thumbs.db
web.config
app.config
database.yml
settings.py
config.php
configuration.php
config.js
config.json
appsettings.json
actuator
actuator/health
actuator/env
actuator/mappings
graphql
graphiql
__graphql
v1
v2
v3
rest
rpc
soap
wsdl
xmlrpc
xmlrpc.php
feed
rss
atom
api-docs
openapi
openapi.json
openapi.yaml
redoc
metrics
trace
health
healthz
readyz
ping
version
about
contact
faq
support
terms
privacy
error
404
500
internal
external
webhook
webhooks
callback
oauth
oauth2
sso
saml
reset
forgot
password
confirm
verify
activate
invite
share
export
import
search
query
filter
report
reports
analytics
stats
statistics
audit
log
logs
access.log
error.log
debug.log
system
service
services
worker
workers
job
jobs
task
tasks
queue
cron
scheduler
deploy
deployment
release
version
changelog
WORDLIST
    WL_DIRS="$BUILTIN_WL"
    WL_FILES="$BUILTIN_WL"
fi

[[ -z "$WL_PARAMS" ]] && WL_PARAMS="$BUILTIN_WL"

# ─── Извлечение чистых URL из httpx_live.txt ─────────────────────────────────
# httpx может выводить: "https://example.com [200] [Title]" или просто "https://example.com"
CLEAN_HOSTS="$FUZZ_DIR/clean_hosts.txt"
awk '{print $1}' "$HTTPX_LIVE" | grep -iE '^https?://' | sort -u > "$CLEAN_HOSTS" || true

HOST_COUNT=$(lc "$CLEAN_HOSTS")

# ─── Проверка инструментов ───────────────────────────────────────────────────
banner "Проверка инструментов"
for t in katana feroxbuster ffuf curl jq python3; do
    if has "$t"; then success "$t"
    else warn "$t — не найден (шаг пропущен)"
    fi
done

echo ""
info "Recon dir      : $RECON_DIR"
info "Fuzzing dir    : $FUZZ_DIR"
info "HTTP хостов    : $HOST_COUNT"
info "Wordlist dirs  : ${WL_DIRS:-встроенный}"
info "Wordlist files : ${WL_FILES:-встроенный}"
info "Wordlist params: ${WL_PARAMS:-встроенный}"

if [[ "$HOST_COUNT" -eq 0 ]]; then
    err "Нет живых HTTP хостов для фаззинга"
    exit 1
fi

# ══════════════════════════════════════════════════════════════════════════════
# МОДУЛЬ 1: CRAWLING — katana
# ══════════════════════════════════════════════════════════════════════════════
banner "1. Crawling — katana"

CRAWL_ALL="$FUZZ_DIR/crawl/all_crawled.txt"
> "$CRAWL_ALL"

if ! has katana; then
    warn "katana не найден: go install github.com/projectdiscovery/katana/cmd/katana@latest"
else
    while IFS= read -r host; do
        [[ -z "$host" ]] && continue
        safe_name=$(echo "$host" | sed 's|https\?://||;s|[/:]|_|g')
        out="$FUZZ_DIR/crawl/${safe_name}.txt"

        info "Краулинг: $host"
        katana \
            -u "$host" \
            -d 3 \
            -jc \
            -kf all \
            -c 10 \
            -p 10 \
            -rd 2 \
            -silent \
            -o "$out" \
            2>/dev/null || true

        if [[ -s "$out" ]]; then
            cat "$out" >> "$CRAWL_ALL"
            success "  katana → $(lc "$out") URL"
        else
            warn "  katana — нет результатов для $host"
        fi
    done < "$CLEAN_HOSTS"

    sort -u "$CRAWL_ALL" -o "$CRAWL_ALL" 2>/dev/null || true
    success "Краулинг завершён → $(lc "$CRAWL_ALL") уникальных URL"
fi

# ══════════════════════════════════════════════════════════════════════════════
# МОДУЛЬ 2: DIRECTORY BRUTEFORCE — feroxbuster
# ══════════════════════════════════════════════════════════════════════════════
banner "2. Directory Bruteforce — feroxbuster"

FEROX_ALL="$FUZZ_DIR/ferox/all_ferox.txt"
> "$FEROX_ALL"

if ! has feroxbuster; then
    warn "feroxbuster не найден: apt install feroxbuster"
else
    while IFS= read -r host; do
        [[ -z "$host" ]] && continue
        safe_name=$(echo "$host" | sed 's|https\?://||;s|[/:]|_|g')
        out_json="$FUZZ_DIR/ferox/${safe_name}.json"
        out_txt="$FUZZ_DIR/ferox/${safe_name}.txt"

        info "feroxbuster: $host"
        feroxbuster \
            --url "$host" \
            --wordlist "$WL_DIRS" \
            --depth 2 \
            --threads 30 \
            --timeout 10 \
            --rate-limit 150 \
            --auto-tune \
            --redirects \
            --filter-status 404,400,503 \
            --output "$out_txt" \
            --json \
            --no-state \
            --quiet \
            2>/dev/null || true

        if [[ -s "$out_txt" ]]; then
            # Извлекаем строки со статусом (не JSON)
            grep -E "^[0-9]{3}" "$out_txt" 2>/dev/null >> "$FEROX_ALL" || true
            success "  feroxbuster → $(lc "$out_txt") строк"
        else
            warn "  feroxbuster — нет результатов для $host"
        fi
    done < "$CLEAN_HOSTS"

    success "Feroxbuster завершён → $(lc "$FEROX_ALL") строк"
fi

# ══════════════════════════════════════════════════════════════════════════════
# МОДУЛЬ 3: FUZZING — ffuf
# ══════════════════════════════════════════════════════════════════════════════
banner "3. Fuzzing — ffuf"

# ── 3a. Fuzzing директорий и файлов ──────────────────────────────────────────
FFUF_DIRS_ALL="$FUZZ_DIR/ffuf/all_dirs.json"
> "$FFUF_DIRS_ALL"

if ! has ffuf; then
    warn "ffuf не найден: go install github.com/ffuf/ffuf/v2@latest"
else
    info "3a. Fuzzing директорий и файлов"
    while IFS= read -r host; do
        [[ -z "$host" ]] && continue
        safe_name=$(echo "$host" | sed 's|https\?://||;s|[/:]|_|g')
        out="$FUZZ_DIR/ffuf/dirs_${safe_name}.json"

        info "  ffuf dirs: $host"
        ffuf \
            -u "${host}/FUZZ" \
            -w "$WL_DIRS" \
            -mc 200,201,204,301,302,307,401,403,405,500 \
            -t 40 \
            -timeout 10 \
            -rate 100 \
            -recursion \
            -recursion-depth 2 \
            -of json \
            -o "$out" \
            -s \
            2>/dev/null || true

        [[ -s "$out" ]] && success "  ffuf dirs → $(jq '.results | length' "$out" 2>/dev/null || echo '?') результатов"
    done < "$CLEAN_HOSTS"

    # ── 3b. Fuzzing параметров GET ────────────────────────────────────────────
    info "3b. Fuzzing GET-параметров (на / каждого хоста)"
    while IFS= read -r host; do
        [[ -z "$host" ]] && continue
        safe_name=$(echo "$host" | sed 's|https\?://||;s|[/:]|_|g')
        out="$FUZZ_DIR/ffuf/params_${safe_name}.json"

        ffuf \
            -u "${host}/?FUZZ=test" \
            -w "$WL_PARAMS" \
            -mc 200,301,302,500 \
            -mr "error|found|success|invalid|bad" \
            -t 30 \
            -timeout 10 \
            -rate 80 \
            -of json \
            -o "$out" \
            -s \
            2>/dev/null || true

        [[ -s "$out" ]] && success "  ffuf params → $(jq '.results | length' "$out" 2>/dev/null || echo '?') результатов"
    done < "$CLEAN_HOSTS"

    # ── 3c. Fuzzing расширений файлов на найденных путях ─────────────────────
    info "3c. Fuzzing backup/config файлов"
    BACKUP_EXT_WL="$FUZZ_DIR/backup_extensions.txt"
    cat > "$BACKUP_EXT_WL" << 'EXTLIST'
.bak
.backup
.old
.orig
.copy
.temp
.tmp
.swp
~
.zip
.tar.gz
.tar
.gz
.rar
.7z
.sql
.sql.gz
.db
.sqlite
.sqlite3
.dump
.env
.env.bak
.env.local
.env.prod
.env.production
.env.development
.env.staging
.git
.gitignore
.gitconfig
.svn
.DS_Store
.htaccess
.htpasswd
config.php.bak
config.php~
wp-config.php.bak
settings.py.bak
database.yml.bak
EXTLIST

    while IFS= read -r host; do
        [[ -z "$host" ]] && continue
        safe_name=$(echo "$host" | sed 's|https\?://||;s|[/:]|_|g')
        out="$FUZZ_DIR/ffuf/backup_${safe_name}.json"

        ffuf \
            -u "${host}/FUZZ" \
            -w "$BACKUP_EXT_WL" \
            -mc 200,201,301,302 \
            -t 20 \
            -timeout 10 \
            -rate 50 \
            -of json \
            -o "$out" \
            -s \
            2>/dev/null || true

        [[ -s "$out" ]] && {
            count=$(jq '.results | length' "$out" 2>/dev/null || echo 0)
            [[ "$count" -gt 0 ]] && success "  ffuf backup → $count НАЙДЕНО! → $host"
        }
    done < "$CLEAN_HOSTS"

    success "ffuf завершён"
fi

# ══════════════════════════════════════════════════════════════════════════════
# МОДУЛЬ 4: JS MINING — поиск endpoint'ов в JS-файлах
# ══════════════════════════════════════════════════════════════════════════════
banner "4. JS Mining — поиск endpoint'ов в JS"

JS_ENDPOINTS="$FUZZ_DIR/js_mining/js_endpoints.txt"
JS_SECRETS="$FUZZ_DIR/js_mining/js_secrets.txt"
> "$JS_ENDPOINTS"
> "$JS_SECRETS"

# Собираем все JS URL из краулинга
JS_URLS="$FUZZ_DIR/js_mining/js_urls.txt"
> "$JS_URLS"

if [[ -s "$CRAWL_ALL" ]]; then
    grep -iE "\.js(\?.*)?$" "$CRAWL_ALL" | sort -u >> "$JS_URLS" || true
fi

# Также ищем JS через curl на каждом хосте
while IFS= read -r host; do
    [[ -z "$host" ]] && continue
    # Пробуем common JS пути
    for jspath in "/main.js" "/app.js" "/bundle.js" "/static/js/main.js" \
                  "/assets/js/app.js" "/js/app.js" "/dist/app.js"; do
        url="${host}${jspath}"
        status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "$url" 2>/dev/null || echo "000")
        [[ "$status" == "200" ]] && echo "$url" >> "$JS_URLS" || true
    done
done < "$CLEAN_HOSTS"

sort -u "$JS_URLS" -o "$JS_URLS" 2>/dev/null || true
JS_COUNT=$(lc "$JS_URLS")
info "JS файлов для анализа: $JS_COUNT"

if [[ "$JS_COUNT" -gt 0 ]]; then
    while IFS= read -r jsurl; do
        [[ -z "$jsurl" ]] && continue
        content=$(curl -s --max-time 15 "$jsurl" 2>/dev/null || true)
        [[ -z "$content" ]] && continue

        # Ищем endpoint'ы
        echo "$content" | \
            grep -oP '["'"'"'`](/[a-zA-Z0-9_/.-]{2,100})["'"'"'`]' 2>/dev/null | \
            tr -d '"'"'" | \
            grep -E '^/' | \
            sort -u | \
            sed "s|^|${jsurl%/*.js}|" >> "$JS_ENDPOINTS" || true

        # Ищем секреты
        echo "$content" | \
            grep -iP '(api[_-]?key|secret|token|password|passwd|bearer|auth[_-]?token|access[_-]?key|private[_-]?key)\s*[:=]\s*["\'"'"'][^"'"'"']{8,}["\'"'"']' \
            2>/dev/null | head -20 | \
            sed "s|^|[${jsurl}] |" >> "$JS_SECRETS" || true
    done < "$JS_URLS"

    sort -u "$JS_ENDPOINTS" -o "$JS_ENDPOINTS" 2>/dev/null || true
    sort -u "$JS_SECRETS" -o "$JS_SECRETS" 2>/dev/null || true
    success "JS Mining → $(lc "$JS_ENDPOINTS") endpoints, $(lc "$JS_SECRETS") потенциальных секретов"
fi

# ══════════════════════════════════════════════════════════════════════════════
# МОДУЛЬ 5: ОБЪЕДИНЕНИЕ И КЛАССИФИКАЦИЯ РЕЗУЛЬТАТОВ
# ══════════════════════════════════════════════════════════════════════════════
banner "5. Объединение результатов"

MERGED_ALL="$FUZZ_DIR/merged/all_endpoints.txt"
> "$MERGED_ALL"

# Из катаны
[[ -s "$CRAWL_ALL" ]] && cat "$CRAWL_ALL" >> "$MERGED_ALL"

# Из feroxbuster — извлекаем URL
if [[ -s "$FEROX_ALL" ]]; then
    grep -oP 'https?://\S+' "$FEROX_ALL" 2>/dev/null >> "$MERGED_ALL" || true
fi

# Из ffuf — парсим JSON
for f in "$FUZZ_DIR/ffuf"/dirs_*.json "$FUZZ_DIR/ffuf"/params_*.json; do
    [[ -f "$f" ]] || continue
    jq -r '.results[]? | .url' "$f" 2>/dev/null >> "$MERGED_ALL" || true
done

# Из backup ffuf
for f in "$FUZZ_DIR/ffuf"/backup_*.json; do
    [[ -f "$f" ]] || continue
    jq -r '.results[]? | .url' "$f" 2>/dev/null >> "$MERGED_ALL" || true
done

# Из JS mining
[[ -s "$JS_ENDPOINTS" ]] && cat "$JS_ENDPOINTS" >> "$MERGED_ALL"

# Финальная сортировка
sort -u "$MERGED_ALL" -o "$MERGED_ALL" 2>/dev/null || true

# ─── Классификация по категориям ─────────────────────────────────────────────
INTERESTING_OUT="$FUZZ_DIR/merged/interesting_endpoints.txt"
PARAMS_OUT="$FUZZ_DIR/merged/endpoints_with_params.txt"
API_OUT="$FUZZ_DIR/merged/api_endpoints.txt"
AUTH_OUT="$FUZZ_DIR/merged/auth_endpoints.txt"
SENSITIVE_OUT="$FUZZ_DIR/merged/sensitive_files.txt"
ERRORS_OUT="$FUZZ_DIR/merged/error_endpoints.txt"

# API endpoint'ы
grep -iE "/(api|v[0-9]+|graphql|rest|rpc|soap|json|xml)(/|$|\?)" \
    "$MERGED_ALL" 2>/dev/null | sort -u > "$API_OUT" || true

# Auth endpoint'ы
grep -iE "/(login|logout|signin|signout|auth|oauth|sso|saml|register|signup|password|reset|forgot|token|refresh)" \
    "$MERGED_ALL" 2>/dev/null | sort -u > "$AUTH_OUT" || true

# Чувствительные файлы
grep -iE "\.(env|git|bak|backup|old|sql|db|sqlite|dump|log|config|cfg|conf|ini|key|pem|p12|pfx|zip|tar|gz|rar)(\?|$)" \
    "$MERGED_ALL" 2>/dev/null | sort -u > "$SENSITIVE_OUT" || true

# URL с параметрами
grep -E "\?.*=" "$MERGED_ALL" 2>/dev/null | sort -u > "$PARAMS_OUT" || true

# Интересные пути (admin, debug, etc.)
grep -iE "/(admin|administrator|dashboard|console|panel|manage|management|debug|test|dev|staging|internal|secret|hidden|backup|config|monitor|metrics|actuator|health|status|info|version)" \
    "$MERGED_ALL" 2>/dev/null | sort -u > "$INTERESTING_OUT" || true

success "Всего уникальных endpoints : $(lc "$MERGED_ALL")"
success "API endpoints              : $(lc "$API_OUT")"
success "Auth endpoints             : $(lc "$AUTH_OUT")"
success "Чувствительные файлы       : $(lc "$SENSITIVE_OUT")"
success "Интересные пути            : $(lc "$INTERESTING_OUT")"
success "URL с параметрами          : $(lc "$PARAMS_OUT")"

# ══════════════════════════════════════════════════════════════════════════════
# МОДУЛЬ 6: ГЕНЕРАЦИЯ ОТЧЁТА
# ══════════════════════════════════════════════════════════════════════════════
banner "6. Генерация отчёта"

{
echo "# 🔎 Fuzz Report"
echo ""
echo "> **Дата:** $(date '+%Y-%m-%d %H:%M:%S')"
echo "> **Recon dir:** \`$RECON_DIR\`"
echo "> **Хостов обработано:** $HOST_COUNT"
echo ""
echo "---"
echo ""

# ── Статистика ─────────────────────────────────────────────────────────────
echo "## 📊 Статистика"
echo ""
echo "| Источник | Найдено |"
echo "|----------|---------|"
echo "| katana (crawl)       | $(lc "$CRAWL_ALL") URL |"
echo "| feroxbuster          | $(lc "$FEROX_ALL") строк |"
echo "| ffuf (dirs)          | $(find "$FUZZ_DIR/ffuf" -name 'dirs_*.json' -exec jq '.results | length' {} \; 2>/dev/null | paste -sd+ | bc 2>/dev/null || echo 0) endpoints |"
echo "| ffuf (backup/config) | $(find "$FUZZ_DIR/ffuf" -name 'backup_*.json' -exec jq '.results | length' {} \; 2>/dev/null | paste -sd+ | bc 2>/dev/null || echo 0) файлов |"
echo "| JS mining            | $(lc "$JS_ENDPOINTS") endpoints |"
echo "| **ИТОГО уникальных** | **$(lc "$MERGED_ALL")** |"
echo ""
echo "---"
echo ""

# ── API endpoints ──────────────────────────────────────────────────────────
if [[ -s "$API_OUT" ]]; then
    echo "## 🔌 API Endpoints ($(lc "$API_OUT"))"
    echo ""
    echo '```'
    head -100 "$API_OUT"
    echo '```'
    echo ""
    echo "---"
    echo ""
fi

# ── Auth endpoints ─────────────────────────────────────────────────────────
if [[ -s "$AUTH_OUT" ]]; then
    echo "## 🔐 Auth / Login Endpoints ($(lc "$AUTH_OUT"))"
    echo ""
    echo '```'
    head -50 "$AUTH_OUT"
    echo '```'
    echo ""
    echo "---"
    echo ""
fi

# ── Sensitive files ────────────────────────────────────────────────────────
if [[ -s "$SENSITIVE_OUT" ]]; then
    echo "## ⚠️  Чувствительные файлы ($(lc "$SENSITIVE_OUT"))"
    echo ""
    echo '```'
    cat "$SENSITIVE_OUT"
    echo '```'
    echo ""
    echo "---"
    echo ""
fi

# ── Interesting paths ──────────────────────────────────────────────────────
if [[ -s "$INTERESTING_OUT" ]]; then
    echo "## 🎯 Интересные пути ($(lc "$INTERESTING_OUT"))"
    echo ""
    echo '```'
    head -100 "$INTERESTING_OUT"
    echo '```'
    echo ""
    echo "---"
    echo ""
fi

# ── JS Secrets ────────────────────────────────────────────────────────────
if [[ -s "$JS_SECRETS" ]]; then
    echo "## 🔑 Потенциальные секреты в JS ($(lc "$JS_SECRETS"))"
    echo ""
    echo '```'
    cat "$JS_SECRETS"
    echo '```'
    echo ""
    echo "---"
    echo ""
fi

# ── URL с параметрами ──────────────────────────────────────────────────────
if [[ -s "$PARAMS_OUT" ]]; then
    echo "## 🔗 URL с параметрами — потенциал XSS/SQLi ($(lc "$PARAMS_OUT"))"
    echo ""
    echo '```'
    head -100 "$PARAMS_OUT"
    echo '```'
    echo ""
    echo "---"
    echo ""
fi

# ── Следующие шаги ────────────────────────────────────────────────────────
echo "## ⚡ Следующие шаги"
echo ""
echo "| Приоритет | Действие |"
echo "|-----------|----------|"
echo "| 🔴 Высокий | Ручная проверка найденных auth endpoint'ов |"
echo "| 🔴 Высокий | Проверка доступности .env, .git, backup файлов |"
echo "| 🔴 Высокий | Анализ потенциальных секретов из JS-файлов |"
echo "| 🟡 Средний | SQL-инъекции в URL с параметрами (sqlmap) |"
echo "| 🟡 Средний | XSS тестирование параметров (dalfox) |"
echo "| 🟡 Средний | Углублённый фаззинг API endpoint'ов |"
echo "| 🟢 Низкий  | Полный анализ всех JS-файлов (LinkFinder) |"
echo "| 🟢 Низкий  | Vhost fuzzing для найденных IP |"

echo ""
echo "---"
echo ""
echo "## 📁 Файлы результатов"
echo ""
echo '```'
find "$FUZZ_DIR" -type f | sort | while read -r f; do
    lines=$(wc -l < "$f" 2>/dev/null || echo 0)
    printf "%-6s строк  %s\n" "$lines" "${f#$RECON_DIR/}"
done
echo '```'

} > "$FUZZ_REPORT"

success "Отчёт → $FUZZ_REPORT"

# ─── Итог ─────────────────────────────────────────────────────────────────────
banner "Готово"

echo -e "${BOLD}📁 Результаты: ${CYAN}${FUZZ_DIR}${NC}"
echo ""
echo -e "  ${GREEN}Всего endpoints     :${NC} $(lc "$MERGED_ALL")"
echo -e "  ${GREEN}API endpoints       :${NC} $(lc "$API_OUT")"
echo -e "  ${GREEN}Auth endpoints      :${NC} $(lc "$AUTH_OUT")"
echo -e "  ${GREEN}Чувствительные файлы:${NC} $(lc "$SENSITIVE_OUT")"
echo -e "  ${GREEN}Интересные пути     :${NC} $(lc "$INTERESTING_OUT")"
echo -e "  ${GREEN}URL с параметрами   :${NC} $(lc "$PARAMS_OUT")"
echo -e "  ${GREEN}JS секреты          :${NC} $(lc "$JS_SECRETS")"
echo ""
echo -e "${BOLD}Просмотр:${NC}"
echo "  cat $FUZZ_REPORT"
echo "  cat $FUZZ_DIR/merged/all_endpoints.txt"
echo "  cat $FUZZ_DIR/merged/sensitive_files.txt"
