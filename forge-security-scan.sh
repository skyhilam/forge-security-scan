#!/usr/bin/env bash
# =============================================================================
# forge-security-scan.sh
#
# 用途：喺本機透過 SSH 掃描一部或多部 Laravel Forge 伺服器，檢查：
#   1-1. PHP 版本係咪已修補 CVE-2026-109618／CVE-2026-109619（2026-10-21）
#   1-2. Node.js（2026-10-21 安全更新）同 Next.js／react-server-dom-*（2026-10-14）版本
#   2. session.upload_progress.enabled 係咪已經設為 Off（臨時緩解）
#   3. 攻擊跡象：
#      3-1 PHP 進程有冇開出可疑子進程（bash、curl、wget、nc、python 等）
#      3-2 Access log 有冇異常 multipart 上傳／PHP_SESSION_UPLOAD_PROGRESS 請求
#      3-3 Web 目錄最近 N 日內新增或修改嘅 .php 檔
#      3-4 有冇可疑嘅新增系統用戶
#
# 注意：
#   - 本腳本「只做檢查」，唔會喺遠端寫入任何檔案、修改設定或重啟服務。
#   - 遠端唔會建立暫存檔，所有結果經 SSH 直接傳返本機。
#   - forge 用戶預設冇免密碼 sudo，部分項目（例如 root 擁有嘅 log）可能無權限讀取，
#     腳本會標示「略過」。如需完整檢查，可以用 -u root 或者為 forge 設定 sudo NOPASSWD。
#   - 本機支援 macOS 內置嘅 bash 3.2；遠端假設為 Forge 預設嘅 Ubuntu + bash。
#
# 用法：
#   ./forge-security-scan.sh 203.0.113.10
#   ./forge-security-scan.sh -i ~/.ssh/id_ed25519 web1.example.com web2.example.com:2222
#   ./forge-security-scan.sh -f servers.txt -d 14 -o ./reports
#   ./forge-security-scan.sh -P                 # 只印出會喺遠端執行嘅腳本（方便審查）
#
# 專案主頁：https://github.com/skyhilam/forge-security-scan
# 授權：MIT
# =============================================================================

VERSION="1.3.0"

# ---------- 預設值 ----------
SSH_USER="forge"      # 預設 SSH 用戶
SSH_PORT=""           # 留空即用 ~/.ssh/config 或 22
SSH_KEY=""            # 私鑰路徑（可選）
DAYS=7                # 檢查最近幾多日
MAX_LINES=20          # 每個項目最多顯示幾多行明細
OUT_DIR=""            # 報告輸出目錄（可選）
SERVER_FILE=""        # 伺服器清單檔（可選）
USE_SUDO=1            # 遠端係咪嘗試用 sudo -n（唔會要求輸入密碼）
USE_COLOR=1           # 係咪輸出顏色
PRINT_REMOTE=0        # 只印出遠端腳本，唔連線
[ -t 1 ] || USE_COLOR=0

# ---------- 顯示用法 ----------
usage() {
    cat <<'EOF'
用法：forge-security-scan.sh [選項] <伺服器> [伺服器...]

伺服器格式：[用戶@]主機[:port]，例如 203.0.113.10、forge@web1.example.com:2222

選項：
  -f FILE   從檔案讀取伺服器清單（每行一部，# 開頭為註解）
  -u USER   SSH 用戶（預設：forge）
  -p PORT   SSH port（預設：跟 ~/.ssh/config，否則 22）
  -i KEY    SSH 私鑰路徑
  -d DAYS   檢查最近幾多日（預設：7）
  -n LINES  每個項目最多顯示幾多行明細（預設：20）
  -o DIR    將每部伺服器嘅報告（純文字）儲存到指定目錄
  -S        遠端唔好嘗試 sudo -n
  -C        唔輸出顏色
  -P        只印出會喺遠端執行嘅腳本（唔會連線），方便審查，
            亦可以喺伺服器上直接執行：... -P | bash -s -- 7 20 1 1
  -V        顯示版本
  -h        顯示呢個說明

結束碼：0 = 全部正常，1 = 有需要注意項目，2 = 有警告，3 = 有伺服器連線失敗
EOF
}

# ---------- 解析參數 ----------
while getopts ":f:u:p:i:d:n:o:SCPVh" opt; do
    case "$opt" in
        f) SERVER_FILE="$OPTARG" ;;
        u) SSH_USER="$OPTARG" ;;
        p) SSH_PORT="$OPTARG" ;;
        i) SSH_KEY="$OPTARG" ;;
        d) DAYS="$OPTARG" ;;
        n) MAX_LINES="$OPTARG" ;;
        o) OUT_DIR="$OPTARG" ;;
        S) USE_SUDO=0 ;;
        C) USE_COLOR=0 ;;
        P) PRINT_REMOTE=1 ;;
        V) echo "forge-security-scan $VERSION"; exit 0 ;;
        h) usage; exit 0 ;;
        :) echo "錯誤：選項 -$OPTARG 需要參數" >&2; usage >&2; exit 64 ;;
        \?) echo "錯誤：未知選項 -$OPTARG" >&2; usage >&2; exit 64 ;;
    esac
done
shift $((OPTIND - 1))

# 數字參數檢查（亦防止傳去遠端時出現注入）
case "$DAYS" in ''|*[!0-9]*) echo "錯誤：-d 必須係正整數" >&2; exit 64 ;; esac
case "$MAX_LINES" in ''|*[!0-9]*) echo "錯誤：-n 必須係正整數" >&2; exit 64 ;; esac
if [ -n "$SSH_PORT" ]; then
    case "$SSH_PORT" in *[!0-9]*) echo "錯誤：-p 必須係數字" >&2; exit 64 ;; esac
fi
[ "$DAYS" -ge 1 ] || DAYS=1
[ "$MAX_LINES" -ge 1 ] || MAX_LINES=1

# ---------- 收集伺服器清單（-P 模式唔需要）----------
SERVERS=()
for s in "$@"; do SERVERS+=("$s"); done
if [ -n "$SERVER_FILE" ]; then
    if [ ! -r "$SERVER_FILE" ]; then
        echo "錯誤：無法讀取伺服器清單檔 $SERVER_FILE" >&2; exit 66
    fi
    while IFS= read -r line || [ -n "$line" ]; do
        line="${line%%#*}"                                  # 去除註解
        line="$(printf '%s' "$line" | tr -d ' \t\r')"       # 去除空白
        [ -n "$line" ] && SERVERS+=("$line")
    done < "$SERVER_FILE"
fi
if [ "$PRINT_REMOTE" = 0 ] && [ "${#SERVERS[@]}" -eq 0 ]; then
    echo "錯誤：請提供最少一部伺服器" >&2; usage >&2; exit 64
fi

# ---------- 本機顏色 ----------
if [ "$USE_COLOR" = 1 ]; then
    L_RED=$'\033[1;31m'; L_YEL=$'\033[1;33m'; L_GRN=$'\033[1;32m'
    L_BLU=$'\033[1;34m'; L_BOLD=$'\033[1m'; L_RST=$'\033[0m'
else
    L_RED=""; L_YEL=""; L_GRN=""; L_BLU=""; L_BOLD=""; L_RST=""
fi

# =============================================================================
# 遠端腳本：經 SSH 嘅 stdin 傳去遠端，由 `bash -s` 執行
# 全部邏輯包喺 main() 入面，最後用 `main "$@" < /dev/null` 執行，
# 確保遠端指令唔會意外讀走 stdin 入面未執行嘅腳本內容。
# =============================================================================
remote_script() {
cat <<'REMOTE_EOF'
# ====== 以下內容喺遠端伺服器執行（只讀檢查，唔會修改任何嘢）======

# ---------- 輸出輔助函數 ----------
section() { printf '\n%s━━━ %s ━━━%s\n' "$C_BLU" "$*" "$C_RST"; }
ok()      { printf '  %s[正常]%s %s\n' "$C_GRN" "$C_RST" "$*"; }
info()    { printf '  %s[資訊]%s %s\n' "$C_CYN" "$C_RST" "$*"; }
skip()    { printf '  %s[略過]%s %s\n' "$C_DIM" "$C_RST" "$*"; }
warn()    { printf '  %s[注意]%s %s\n' "$C_YEL" "$C_RST" "$*"; WARNS=$((WARNS + 1)); FINDINGS+=("${C_YEL}[注意]${C_RST} $*"); }
alert()   { printf '  %s[警告]%s %s\n' "$C_RED" "$C_RST" "$*"; ALERTS=$((ALERTS + 1)); FINDINGS+=("${C_RED}[警告]${C_RST} $*"); }

# 縮排顯示明細（由 stdin 讀入），最多 MAX_LINES 行，每行最多 300 字元
detail() {
    local n=0 line max="${1:-$MAX_LINES}"
    while IFS= read -r line; do
        [ -z "$line" ] && continue
        n=$((n + 1))
        [ "$n" -le "$max" ] && printf '        %s%s%s\n' "$C_DIM" "${line:0:300}" "$C_RST"
    done
    [ "$n" -gt "$max" ] && printf '        %s…… 仲有 %d 行未顯示（可用 -n 調整）%s\n' "$C_DIM" $((n - max)) "$C_RST"
    return 0
}

# 計算字串行數（空字串為 0）
count_lines() { if [ -z "$1" ]; then echo 0; else printf '%s\n' "$1" | grep -c .; fi; }

# Unix 時間轉為可讀格式
fmt_ts() { date -d "@$1" '+%Y-%m-%d %H:%M' 2>/dev/null; }

# 將 ini 值統一轉為 On / Off（PHP 視 0/off/false/no/空白 為關閉）
norm_bool() {
    local s="${1%%;*}"
    s=$(printf '%s' "$s" | tr -d " \t\"'\r" | tr 'A-Z' 'a-z')
    case "$s" in 0|off|false|no|none|"") echo "Off" ;; *) echo "On" ;; esac
}

# 由 phpinfo 輸出（純文字或 HTML）攞某個設定嘅 Local Value
info_get() {
    printf '%s\n' "$1" | grep -m1 -E "(^|>)$2( |<)" \
        | sed -e 's/<[^>]*>/ /g' -e 's/=>/ /g' | awk '{print $2}'
}

# 以可用權限執行「唯讀」指令：有免密碼 sudo 就用 sudo -n，否則直接執行
priv() { if [ "$SUDO_OK" = 1 ]; then sudo -n "$@"; else "$@"; fi; }

# 判斷某版本 PHP-FPM 係咪運行緊，同埋攞 master PID
fpm_running()    { ps -eo args= 2>/dev/null | grep -q "^php-fpm: master process (/etc/php/$1/"; }
fpm_master_pid() { ps -eo pid=,args= 2>/dev/null | awk -v p="master process (/etc/php/$1/" 'index($0, p) {print $1; exit}'; }

# ---------- 已修補版本（有新安全公告時更新呢度）----------
PHP_FIXED="8.2.35 8.3.36 8.4.27 8.5.12"    # CVE-2026-109618 / CVE-2026-109619（2026-10-21）
NODE_FIXED="22.23.4 24.22.1 26.12.1"       # Node.js 2026-10-21 Security Releases
NEXT_FIXED="15.5.28 16.4.1"                # Next.js 2026-10-14 安全更新
RSC_FIXED="19.0.9 19.1.10 19.2.9 19.3.1"   # react-server-dom-*（2026-10-14）

# ver_lt A B：A < B 就回傳 0（只比較頭三段數字）
ver_lt() {
    awk -v a="$1" -v b="$2" 'BEGIN {
        split(a, x, /[.+-]/); split(b, y, /[.+-]/)
        for (i = 1; i <= 3; i++) { if ((x[i] + 0) < (y[i] + 0)) exit 0; if ((x[i] + 0) > (y[i] + 0)) exit 1 }
        exit 1 }'
}
# 取版本嘅頭 N 段，例如 branch_of 8.3.12 2 → 8.3
branch_of() { printf '%s' "$1" | cut -d. -f1-"$2"; }
# 喺修補清單入面搵同一分支嘅修補版本
fixed_for() {
    local f
    for f in $1; do
        [ "$(branch_of "$f" "$3")" = "$(branch_of "$2" "$3")" ] && { echo "$f"; return; }
    done
}
# PHP-FPM 最後啟動／reload 嘅時間，輸出「epoch 有冇可靠證據(1/0)」
fpm_loaded_time() {
    local v="$1" mpid et loaded evidence=0 pidf pm last_ready le
    mpid=$(fpm_master_pid "$v")
    et=$(ps -o etimes= -p "$mpid" 2>/dev/null | tr -d ' ')
    loaded=$((NOW - ${et:-0}))
    # FPM 每次 start／reload 都會重寫 pid 檔（唔使 sudo 都讀到修改時間）
    pidf=$(awk -F= '/^[[:space:]]*pid[[:space:]]*=/ {gsub(/[[:space:]]/, "", $2); print $2; exit}' "/etc/php/$v/fpm/php-fpm.conf" 2>/dev/null)
    pm=$(stat -c %Y "${pidf:-/run/php/php$v-fpm.pid}" 2>/dev/null)
    if [ -n "$pm" ]; then evidence=1; [ "$pm" -gt "$loaded" ] && loaded=$pm; fi
    # 後備：FPM log 嘅 "ready to handle connections"（通常要 sudo 先讀到）
    last_ready=$(priv tail -n 5000 "/var/log/php$v-fpm.log" 2>/dev/null \
        | grep -a 'ready to handle connections' | tail -n1 | sed -E 's/^\[([^]]+)\].*/\1/')
    if [ -n "$last_ready" ]; then
        le=$(date -d "$(printf '%s' "$last_ready" | tr '-' ' ')" +%s 2>/dev/null)
        if [ -n "$le" ]; then evidence=1; [ "$le" -gt "$loaded" ] && loaded=$le; fi
    fi
    echo "$loaded $evidence"
}

# 升級咗 PHP 但 FPM 未重啟：運行中嘅仍然係舊程式。輸出原因，冇問題就冇輸出
fpm_stale() {
    local v="$1" mpid bin pid exe loaded evidence bct
    mpid=$(fpm_master_pid "$v")
    [ -n "$mpid" ] || return 0
    bin="/usr/sbin/php-fpm$v"
    # 方法一（直接證據）：程式檔被取代後，運行中進程嘅 /proc/<pid>/exe 會顯示 (deleted)。
    # master 屬 root（要 sudo），worker 通常屬 forge（唔使 sudo）
    for pid in "$mpid" $(ps -o pid= --ppid "$mpid" 2>/dev/null); do
        exe=$(priv readlink "/proc/$pid/exe" 2>/dev/null)
        case "$exe" in *" (deleted)") echo "運行中嘅 FPM 進程（PID $pid）用緊已被取代嘅舊程式檔"; return 0 ;; esac
    done
    # 方法二（後備）：程式檔嘅 ctime（實際安裝時間，dpkg 改唔到）晚過 FPM 最後載入時間
    read -r loaded evidence <<< "$(fpm_loaded_time "$v")"
    bct=$(stat -L -c %Z "$bin" 2>/dev/null)
    if [ -n "$bct" ] && [ "$evidence" = 1 ] && [ "$bct" -gt "$loaded" ]; then
        echo "程式檔喺 $(fmt_ts "$bct") 更新，但 FPM 最後載入時間係 $(fmt_ts "$loaded")"
    fi
}

# Node.js 版本狀態：ok／vuln（低過修補版本）／eol（已停止支援）／unknown
node_state() {
    local ver="$1" major fixed
    major=${ver%%.*}
    fixed=$(fixed_for "$NODE_FIXED" "$ver" 1)
    if [ -n "$fixed" ]; then
        if ver_lt "$ver" "$fixed"; then echo vuln; else echo ok; fi
    elif [ "$major" -lt 22 ] 2>/dev/null || [ "$major" = 23 ] || [ "$major" = 25 ]; then
        echo eol
    else
        echo unknown
    fi
}
# 讀 package.json 嘅 version
pkg_version() { grep -oE '"version"[[:space:]]*:[[:space:]]*"[^"]+"' "$1" 2>/dev/null | head -n1 | sed -E 's/.*"([^"]+)"$/\1/'; }
# 提示行（縮排、暗色）
hint() { printf '        %s%s%s\n' "$C_DIM" "$*" "$C_RST"; }

main() {
    DAYS="${1:-7}"
    MAX_LINES="${2:-20}"
    USE_COLOR="${3:-1}"
    USE_SUDO="${4:-1}"
    export LC_ALL=C
    NOW=$(date +%s)
    WINDOW=$((DAYS * 86400))
    ALERTS=0
    WARNS=0
    FINDINGS=()

    if [ "$USE_COLOR" = 1 ]; then
        C_RED=$'\033[1;31m'; C_YEL=$'\033[1;33m'; C_GRN=$'\033[1;32m'
        C_BLU=$'\033[1;34m'; C_CYN=$'\033[36m'; C_DIM=$'\033[2m'; C_RST=$'\033[0m'
    else
        C_RED=""; C_YEL=""; C_GRN=""; C_BLU=""; C_CYN=""; C_DIM=""; C_RST=""
    fi

    # 權限判斷：root 或者有免密碼 sudo 先可以讀 root 擁有嘅檔案
    IS_ROOT=0; [ "$(id -u)" = 0 ] && IS_ROOT=1
    SUDO_OK=0
    if [ "$IS_ROOT" = 0 ] && [ "$USE_SUDO" = 1 ] && command -v sudo >/dev/null 2>&1 \
        && sudo -n true >/dev/null 2>&1; then
        SUDO_OK=1
    fi
    HAS_PRIV=0; { [ "$IS_ROOT" = 1 ] || [ "$SUDO_OK" = 1 ]; } && HAS_PRIV=1

    # 常用：PHP 檔副檔名（find 用）
    PHP_EXT=( \( -iname '*.php' -o -iname '*.phtml' -o -iname '*.php[0-9]' -o -iname '*.phar' -o -iname '*.pht' -o -iname '*.phps' \) )

    # =========================================================================
    section "伺服器資訊"
    # =========================================================================
    info "主機名稱：$(hostname -f 2>/dev/null || hostname)"
    info "作業系統：$(. /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-未知}")，核心 $(uname -r)"
    info "運行時間：$(uptime -p 2>/dev/null || uptime)"
    if [ "$IS_ROOT" = 1 ]; then
        info "執行身份：root（可完整檢查）"
    elif [ "$SUDO_OK" = 1 ]; then
        info "執行身份：$(id -un)，有免密碼 sudo（只用於讀取）"
    else
        info "執行身份：$(id -un)，冇免密碼 sudo（部分 root 擁有嘅檔案會略過）"
    fi
    info "檢查範圍：最近 ${DAYS} 日"

    # 作業系統標準支援期：過咗之後系統套件同 Forge 用嘅 ondrej PHP 套件源都唔會再有更新
    OS_EOL=0
    os_key=$(. /etc/os-release 2>/dev/null; echo "${ID:-}:${VERSION_ID:-}")
    case "$os_key" in
        ubuntu:16.04) os_end="2021-04-30" ;;
        ubuntu:18.04) os_end="2023-05-31" ;;
        ubuntu:20.04) os_end="2025-05-29" ;;
        debian:9)     os_end="2022-06-30" ;;
        debian:10)    os_end="2024-06-30" ;;
        debian:11)    os_end="2026-08-31" ;;
        *)            os_end="" ;;
    esac
    if [ -n "$os_end" ] && [ "$(date -d "$os_end" +%s 2>/dev/null || echo "$NOW")" -lt "$NOW" ]; then
        OS_EOL=1
        warn "作業系統 ${os_key/:/ } 已於 $os_end 停止標準支援：系統套件同 Forge 用嘅 PHP 套件源（ondrej）都唔會再有修補"
        hint "apt 攞唔到最新修補；建議開一部新嘅 Forge 伺服器（Ubuntu 24.04）再搬網站"
    fi

    # 雲端平台同 cloud-init 預設用戶（例如 AWS 嘅 ubuntu）
    CLOUD_USER=$(awk '/^[[:space:]]*default_user:/ {f = 1; next} f && /^[[:space:]]*name:/ {print $2; exit} f && /^[^[:space:]#]/ {exit}' /etc/cloud/cloud.cfg 2>/dev/null)
    CLOUD_NAME=""
    case "$(cat /sys/class/dmi/id/sys_vendor 2>/dev/null)" in
        *Amazon*) CLOUD_NAME="AWS" ;; *Google*) CLOUD_NAME="Google Cloud" ;; *Microsoft*) CLOUD_NAME="Azure" ;;
        *DigitalOcean*) CLOUD_NAME="DigitalOcean" ;; *Hetzner*) CLOUD_NAME="Hetzner" ;; *Linode*|*Akamai*) CLOUD_NAME="Linode" ;;
    esac
    [ -n "$CLOUD_NAME" ] && info "雲端平台：$CLOUD_NAME"

    # =========================================================================
    section "1-1. PHP 版本（CVE-2026-109618／CVE-2026-109619）"
    # =========================================================================
    PHP_VERSIONS=$(find /etc/php -mindepth 1 -maxdepth 1 -type d -printf '%f\n' 2>/dev/null | grep -E '^[0-9]+\.[0-9]+$' | sort -V)
    if command -v php >/dev/null 2>&1; then
        info "預設 php 指令：$(php -r 'echo PHP_VERSION;' 2>/dev/null)（$(readlink -f "$(command -v php)")）"
    else
        warn "搵唔到 php 指令"
    fi
    [ -z "$PHP_VERSIONS" ] && warn "/etc/php 下面搵唔到任何已安裝嘅 PHP 版本"
    info "已修補版本：$(printf '%s' "$PHP_FIXED" | sed 's/ /／/g')（2026-10-21；官方：升級係唯一完整修補）"
    declare -A PHP_STATE    # 每個 PHP 版本嘅狀態，1-3 網站對應會用：ok／vuln／eol／unknown

    for v in $PHP_VERSIONS; do
        full=""
        [ -x "/usr/bin/php$v" ] && full=$("/usr/bin/php$v" -r 'echo PHP_VERSION;' 2>/dev/null)
        if [ -x "/usr/sbin/php-fpm$v" ]; then
            [ -z "$full" ] && full=$("/usr/sbin/php-fpm$v" -v 2>/dev/null | awk 'NR==1 {print $2}')
            if fpm_running "$v"; then st="FPM 運行中"; else st="FPM 未運行"; fi
        else
            st="冇安裝 FPM"
        fi
        msg="PHP ${full:-$v}（$st）"
        fixed=$(fixed_for "$PHP_FIXED" "${full:-$v}" 2)

        # Ubuntu／Debian 官方套件會 backport 修補但唔改版本號，所以要睇套件 changelog
        backport=0
        for pkg in "php$v-fpm" "php$v-common" "php$v-cli"; do
            cl=$(zcat -f "/usr/share/doc/$pkg/changelog.Debian.gz" 2>/dev/null | head -n 400)
            if printf '%s' "$cl" | grep -q 'CVE-2026-109618' && printf '%s' "$cl" | grep -q 'CVE-2026-109619'; then
                backport=1; break
            fi
        done
        pkgver=$(dpkg-query -W -f='${Version}' "php$v-common" 2>/dev/null)

        if [ -z "$full" ]; then
            PHP_STATE[$v]=unknown
            info "$msg：無法取得完整版本號"
        elif [ -n "$fixed" ] && ! ver_lt "$full" "$fixed"; then
            PHP_STATE[$v]=ok
            ok "$msg：已包含 2026-10-21 嘅修補"
        elif [ "$backport" = 1 ]; then
            PHP_STATE[$v]=ok
            ok "$msg：套件 changelog 顯示已 backport CVE-2026-109618／109619 修補（$pkgver）"
        elif [ -z "$fixed" ] && ! ver_lt "$full" "8.2.0"; then
            PHP_STATE[$v]=unknown
            info "$msg：唔喺 2026-10-21 公告列出嘅分支，請自行確認"
        else
            if [ -n "$fixed" ]; then why="低過已修補版本 $fixed"; PHP_STATE[$v]=vuln; else why="已停止官方支援（EOL），冇官方修補"; PHP_STATE[$v]=eol; fi
            if [ "$st" = "FPM 運行中" ]; then
                alert "$msg：$why，受 CVE-2026-109618／CVE-2026-109619（未經驗證遠端執行程式碼）影響，請立即升級"
            else
                warn "$msg：$why（FPM 冇運行，網頁暫時唔受影響，仍建議升級）"
            fi
            if [ "$OS_EOL" = 1 ] && [ -z "$fixed" ]; then
                hint "PHP $v 冇官方修補，而且作業系統已停止支援：要開新伺服器（Ubuntu 24.04），並將網站轉去 PHP 8.3／8.4"
            elif [ "$OS_EOL" = 1 ]; then
                hint "作業系統已停止支援，apt 攞唔到 $fixed：要開新伺服器（Ubuntu 24.04）搬網站，或者用付費 PHP LTS（例如 Freexian）"
            elif [ -n "$fixed" ]; then
                hint "升級：sudo apt-get update && sudo apt-get install --only-upgrade 'php$v-*'，再喺 Forge 重啟 PHP"
            else
                hint "PHP $v 冇官方修補，要轉去 8.2 或以上嘅已修補版本"
            fi
            case "$pkgver" in *ubuntu*|*deb1[0-9]u*) case "$pkgver" in *sury*) ;; *) hint "呢個係發行版官方套件（$pkgver），修補會以 backport 形式推出，請留意 Ubuntu／Debian 安全公告" ;; esac ;; esac
            hint "未能即時升級：官方臨時措施係 session.upload_progress.enabled=0、memory_limit=-1$( [ "$(branch_of "$full" 2)" = 8.5 ] && echo '、fatal_error_backtraces=0')，然後重啟所有 worker（唔完整，只可以爭取時間）"
        fi
        # 硬碟上嘅版本已修補，但 FPM 未重啟嘅話，運行緊嘅仍然係舊版
        if [ "${PHP_STATE[$v]}" = ok ] && [ "$st" = "FPM 運行中" ]; then
            stale=$(fpm_stale "$v")
            if [ -n "$stale" ]; then
                PHP_STATE[$v]=stale
                alert "PHP $v：已升級但 FPM 未重啟，運行緊嘅仍然係舊版，漏洞未修補（$stale）"
                hint "喺 Forge 按「Restart PHP」，或者 sudo service php$v-fpm restart，然後再跑一次確認"
            fi
        fi
        [ "$(branch_of "${full:-$v}" 2)" = "8.2" ] && info "PHP 8.2 官方安全支援至 2026-12-31，請準備升級"
    done

    # =========================================================================
    section "1-2. Node.js／Next.js 版本"
    # =========================================================================
    info "已修補版本：Node.js $(printf '%s' "$NODE_FIXED" | sed 's/ /／/g')（2026-10-21）；Next.js $(printf '%s' "$NEXT_FIXED" | sed 's/ /／/g')（2026-10-14）"

    # 運行中嘅 node 進程（包括 Next.js 正式環境嘅 next-server）
    # 注意：next-server 會改進程名稱（入面有空格），所以直接比對成行
    NODE_PROCS=$(ps -eo pid=,user=,comm=,args= 2>/dev/null | awk '$3 == "node" || $3 == "nodejs" || /next-server \(v/')
    RUNNING_EXES=$(printf '%s\n' "$NODE_PROCS" | awk 'NF {print $1}' | while read -r pid; do
                       exe=$(readlink "/proc/$pid/exe" 2>/dev/null)
                       case "$exe" in ""|*" (deleted)") ;; *) readlink -f "/proc/$pid/exe" ;; esac
                   done | sort -u)

    # 已安裝嘅 node：PATH、常見位置、nvm／volta／fnm
    NODE_BINS=$( { command -v node nodejs
                   ls -1d /usr/bin/node /usr/local/bin/node /opt/*/bin/node \
                          /home/*/.nvm/versions/node/*/bin/node /root/.nvm/versions/node/*/bin/node \
                          /home/*/.volta/tools/image/node/*/bin/node \
                          /home/*/.local/share/fnm/node-versions/*/installation/bin/node
                   printf '%s\n' "$RUNNING_EXES"; } 2>/dev/null \
                 | while read -r b; do [ -n "$b" ] && [ -x "$b" ] && readlink -f "$b"; done | sort -u)

    if [ -z "$NODE_BINS" ] && [ -z "$NODE_PROCS" ]; then
        ok "冇發現 Node.js"
    fi
    for b in $NODE_BINS; do
        ver=$("$b" -v 2>/dev/null); ver=${ver#v}
        [ -z "$ver" ] && continue
        running=0; printf '%s\n' "$RUNNING_EXES" | grep -qxF "$b" && running=1
        if [ "$running" = 1 ]; then label="Node.js $ver（$b，有進程運行中）"; else label="Node.js $ver（$b）"; fi
        major=${ver%%.*}
        fixed=$(fixed_for "$NODE_FIXED" "$ver" 1)
        problem=""
        if [ -n "$fixed" ]; then
            if ver_lt "$ver" "$fixed"; then problem="低過已修補版本 $fixed"; else ok "$label：已包含 2026-10-21 嘅修補"; fi
        elif [ "$major" -lt 22 ] || [ "$major" = 23 ] || [ "$major" = 25 ]; then
            problem="已停止官方支援（EOL），冇修補"
        else
            info "$label：唔喺 2026-10-21 公告列出嘅版本，請自行確認"
        fi
        [ -z "$problem" ] && continue
        if [ "$running" = 1 ]; then
            alert "$label：$problem（包括 Brotli 解壓 RCE CVE-2026-111497 等 High 級漏洞）"
        else
            warn "$label：$problem（如果只係用嚟 build 前端，風險較低，但建議升級）"
        fi
    done
    # 程式檔被取代（例如 apt 升級咗 /usr/bin/node）但進程未重啟：運行緊嘅係舊版
    node_stale=$(printf '%s\n' "$NODE_PROCS" | awk 'NF {print $1}' | while read -r pid; do
                     exe=$(readlink "/proc/$pid/exe" 2>/dev/null)
                     case "$exe" in *" (deleted)") echo "PID $pid | ${exe% (deleted)} | $(readlink -f "/proc/$pid/cwd" 2>/dev/null)" ;; esac
                 done)
    if [ -n "$node_stale" ]; then
        alert "有 Node.js 進程運行緊已被取代嘅舊程式（升級咗但未重啟，版本未知，當未修補處理）："
        printf '%s\n' "$node_stale" | detail 999
        hint "重啟呢啲服務（例如 pm2 restart <app>，或者喺 Forge 重啟 daemon），然後再跑一次確認"
    fi
    other_procs=$(printf '%s\n' "$NODE_PROCS" | awk 'NF {print $1, $2}' | while read -r pid user; do
                      [ -z "$(readlink -f "/proc/$pid/exe" 2>/dev/null)" ] && echo "PID $pid | 用戶 $user | $(ps -o args= -p "$pid" 2>/dev/null)"
                  done)
    if [ -n "$other_procs" ]; then
        info "以下 node 進程無權限讀取執行檔，唔知用緊邊個 Node.js（通常係其他用戶嘅進程，需要 sudo）："
        printf '%s\n' "$other_procs" | detail
    fi

    # Next.js：運行中嘅 next-server 會喺進程名稱顯示版本
    next_running=$(printf '%s\n' "$NODE_PROCS" | grep -oE 'next-server \(v[^)]+\)' | sed -E 's/.*\(v([^)]+)\)/\1/' | sort -u)
    # Next.js 同 react-server-dom-*：已部署專案入面嘅 node_modules
    NEXT_PKGS=$(find /home /var/www -maxdepth 8 -path '*/node_modules/next/package.json' \
                    ! -path '*/node_modules/*/node_modules/*' 2>/dev/null | sort)
    RSC_PKGS=$(find /home /var/www -maxdepth 8 -path '*/node_modules/react-server-dom-*/package.json' \
                   ! -path '*/node_modules/*/node_modules/*' 2>/dev/null | sort)

    check_next() {      # check_next <版本> <描述>
        local v="$1" where="$2" major fixed
        major=${v%%.*}
        fixed=$(fixed_for "$NEXT_FIXED" "$v" 1)
        if [ -n "$fixed" ]; then
            if ver_lt "$v" "$fixed"; then
                alert "Next.js $v（$where）：低過 $fixed，受 2026-10-14 公布嘅未經驗證 RCE 影響，請升級"
            else
                ok "Next.js $v（$where）：已包含 2026-10-14 嘅修補"
            fi
        elif [ "$major" -ge 10 ] 2>/dev/null && [ "$major" -le 14 ]; then
            alert "Next.js $v（$where）：受 Image Optimization SVG RCE 影響而且冇官方修補，請升級到 15.5.28 或 16.4.1 以上"
        else
            info "Next.js $v（$where）：唔喺公告列出嘅受影響範圍，請自行確認"
        fi
    }
    for nv in $next_running; do check_next "$nv" "運行中嘅 next-server"; done
    for f in $NEXT_PKGS; do
        nv=$(pkg_version "$f"); [ -n "$nv" ] && check_next "$nv" "${f%/node_modules/*}"
    done
    for f in $RSC_PKGS; do
        rv=$(pkg_version "$f"); [ -z "$rv" ] && continue
        name=$(basename "$(dirname "$f")")
        fixed=$(fixed_for "$RSC_FIXED" "$rv" 2)
        if [ -n "$fixed" ] && ver_lt "$rv" "$fixed"; then
            alert "$name $rv（${f%/node_modules/*}）：低過 $fixed，受 React Server Components 未經驗證 RCE 影響"
        elif [ -n "$fixed" ]; then
            ok "$name $rv（${f%/node_modules/*}）：已修補"
        fi
    done
    [ -z "$next_running$NEXT_PKGS$RSC_PKGS" ] && [ -n "$NODE_BINS" ] && info "冇發現已部署嘅 Next.js 專案"

    # =========================================================================
    section "1-3. 網站對應：每個網站由邊個 PHP／Node.js 處理請求"
    # =========================================================================
    # 監聽緊嘅 port → PID（冇 sudo 只睇到自己用戶嘅進程）
    LISTEN=$(ss -ltnpH 2>/dev/null | awk '{
        n = split($4, a, ":"); port = a[n]; rest = $0
        while (match(rest, /pid=[0-9]+/)) { print port, substr(rest, RSTART + 4, RLENGTH - 4); rest = substr(rest, RSTART + RLENGTH) }
    }' | sort -u)
    # 所有監聽中嘅 port（唔使 sudo 都睇到，只係睇唔到屬邊個進程）
    LISTEN_ALL=" $(ss -ltnH 2>/dev/null | awk '{n = split($4, a, ":"); print a[n]}' | sort -u | tr '\n' ' ')"
    declare -A NODE_VER_CACHE
    # 讀取 PID 嘅資料，結果放入 PN_NAME／PN_VER／PN_STATE／PN_CWD（唔用 subshell，等快取有效）
    pid_info() {
        local exe
        exe=$(readlink "/proc/$1/exe" 2>/dev/null)
        case "$exe" in *" (deleted)") ;; ?*) exe=$(readlink -f "/proc/$1/exe" 2>/dev/null) ;; esac
        PN_CWD=$(readlink -f "/proc/$1/cwd" 2>/dev/null)
        PN_NAME=$(basename "${exe:-?}"); PN_VER=""; PN_STATE=other
        case "$exe" in
            */node" (deleted)"|*/nodejs" (deleted)")
                PN_NAME="Node.js（舊版，程式檔已被取代）"; PN_VER=""; PN_STATE=stale ;;
            */node|*/nodejs)
                [ -z "${NODE_VER_CACHE[$exe]+x}" ] && NODE_VER_CACHE[$exe]=$("$exe" -v 2>/dev/null | tr -d v)
                PN_NAME="Node.js"; PN_VER=${NODE_VER_CACHE[$exe]}; PN_STATE=$(node_state "$PN_VER") ;;
            "") PN_NAME="?"; PN_STATE=noperm ;;
        esac
    }

    PHP_BAD=""; PHP_GOOD=""; NODE_BAD=""; NODE_GOOD=""; SITE_UNKNOWN=""; STATIC_SITES=""; MAPPED_PIDS=" "
    DIRECT_BAD=""; NO_PHP_FILES=0
    if [ ! -d /etc/nginx/sites-enabled ]; then
        skip "搵唔到 /etc/nginx/sites-enabled"
    else
        for conf in /etc/nginx/sites-enabled/*; do
            [ -f "$conf" ] || continue
            cname=$(basename "$conf")
            # 網站設定 + Forge 嘅 include（forge-conf/<網站>/before|server|after），去除註解
            cbody=$(cat "$conf" /etc/nginx/forge-conf/"$cname"/*/* 2>/dev/null | sed 's/#.*//')
            # 用字詞比對（設定可能寫晒喺同一行）；Forge 自動加嘅 www. 別名唔重複顯示
            names=$(printf '%s\n' "$cbody" | grep -oE '(^|[[:space:];{])server_name[[:space:]]+[^;]+' | sed -E 's/.*server_name[[:space:]]+//' \
                    | tr -s ' \t' '\n\n' | grep -vxE '_|' | sort -u \
                    | awk '{n[$0] = 1} END {for (x in n) if (!(x ~ /^www\./ && (substr(x, 5) in n))) print x}' | sort)
            others=$(printf '%s\n' $names | grep -vxF "$cname" | tr '\n' ' '); others=${others% }
            if [ -z "$names" ]; then label="$cname"
            elif printf '%s\n' $names | grep -qxF "$cname"; then label="$cname${others:+（另有 $others）}"
            else label="$cname（server_name：$others）"; fi
            # 預設網站或者 server_name 係 IP：直接用伺服器 IP 就連到，繞過 Cloudflare
            direct=0
            if printf '%s\n' "$cbody" | grep -qE 'listen[^;]*default_server' || printf '%s\n' $names | grep -qE '^[0-9]+(\.[0-9]+){3}$'; then
                direct=1; label="$label【可以用伺服器 IP 直接連入】"
            fi
            # 網站目錄（用嚟判斷有冇 PHP 檔）
            wroot=$(printf '%s\n' "$cbody" | grep -oE '(^|[[:space:];{])root[[:space:]]+[^;]+' | head -n1 | sed -E 's/.*root[[:space:]]+//')

            # PHP：fastcgi_pass unix:/var/run/php/php8.3-fpm.sock（網站隔離會係 php8.3-fpm-<用戶>.sock）
            phpvs=$(printf '%s\n' "$cbody" | grep -oE 'php[0-9]+\.[0-9]+-fpm' | sed -E 's/php([0-9.]+)-fpm/\1/' | sort -u)
            # Node.js 等：proxy_pass http://127.0.0.1:3000，或者經 upstream
            ports=$(printf '%s\n' "$cbody" | grep -oE 'proxy_pass[[:space:]]+https?://(127\.0\.0\.1|localhost|0\.0\.0\.0|\[::1\])?:[0-9]+' | grep -oE '[0-9]+$')
            for up in $(printf '%s\n' "$cbody" | grep -oE 'proxy_pass[[:space:]]+https?://[A-Za-z_][A-Za-z0-9_.-]*' | sed -E 's#.*://##' | grep -vE '^localhost$'); do
                up_re=$(printf '%s' "$up" | sed 's/\./\\./g')
                ports="$ports $(cat /etc/nginx/conf.d/*.conf /etc/nginx/sites-enabled/* 2>/dev/null | sed 's/#.*//' | tr '\n' ' ' \
                    | grep -oE "upstream[[:space:]]+${up_re}[[:space:]]*\{[^}]*\}" | grep -oE ':[0-9]+' | tr -d ':')"
            done
            ports=$(printf '%s\n' $ports | sort -un)

            handled=0
            # nginx 有 PHP location，但網站目錄根本冇 PHP 檔（例如純 Node.js 網站）→ 可以刪走 PHP location
            phpnote=""
            if [ -n "$phpvs" ] && [ -n "$wroot" ]; then
                if [ ! -d "$wroot" ]; then
                    phpnote="；網站目錄 $wroot 唔存在"
                elif [ -r "$wroot" ] && [ -z "$(find "$wroot" -maxdepth 2 -name '*.php' -print -quit 2>/dev/null)" ]; then
                    phpnote="；網站目錄冇 PHP 檔，可以喺 nginx 刪走 PHP location"
                    NO_PHP_FILES=$((NO_PHP_FILES + 1))
                fi
            fi
            for pv in $phpvs; do
                handled=1
                case "${PHP_STATE[$pv]:-missing}" in
                    ok)      PHP_GOOD+="$label → PHP $pv"$'\n' ;;
                    vuln)    PHP_BAD+="$label → PHP $pv（未修補$phpnote）"$'\n'; [ "$direct" = 1 ] && DIRECT_BAD+="$cname → PHP $pv"$'\n' ;;
                    eol)     PHP_BAD+="$label → PHP $pv（已停止支援，冇修補$phpnote）"$'\n'; [ "$direct" = 1 ] && DIRECT_BAD+="$cname → PHP $pv"$'\n' ;;
                    stale)   PHP_BAD+="$label → PHP $pv（已升級但 FPM 未重啟，運行緊舊版$phpnote）"$'\n'; [ "$direct" = 1 ] && DIRECT_BAD+="$cname → PHP $pv"$'\n' ;;
                    missing) SITE_UNKNOWN+="$label → PHP $pv（呢部機冇安裝呢個版本嘅 FPM）"$'\n' ;;
                    *)       SITE_UNKNOWN+="$label → PHP $pv（版本狀態未能確認）"$'\n' ;;
                esac
            done
            for port in $ports; do
                handled=1
                pids=$(printf '%s\n' "$LISTEN" | awk -v p="$port" '$1 == p {print $2}')
                if [ -z "$pids" ]; then
                    case "$LISTEN_ALL" in
                        *" $port "*) SITE_UNKNOWN+="$label → port $port（有服務監聽緊，但屬其他用戶，例如 root、pm2 或者 Docker；需要 sudo 先睇到版本）"$'\n' ;;
                        *)           SITE_UNKNOWN+="$label → port $port（冇服務監聽：如果網站仍然有回應，即係已搬去其他伺服器，呢度係舊設定；否則 nginx 會回 502。冇用嘅話建議刪走網站設定）"$'\n' ;;
                    esac
                    continue
                fi
                declare -A seen=()
                for pid in $pids; do
                    MAPPED_PIDS+="$pid "
                    pid_info "$pid"
                    key="$PN_NAME|$PN_VER|$PN_CWD"
                    [ -n "${seen[$key]+x}" ] && continue
                    seen[$key]=1
                    desc="$label → port $port → $PN_NAME${PN_VER:+ $PN_VER}（${PN_CWD:-PID $pid}）"
                    case "$PN_STATE" in
                        ok)     NODE_GOOD+="$desc"$'\n' ;;
                        vuln)   NODE_BAD+="$desc：未修補"$'\n' ;;
                        eol)    NODE_BAD+="$desc：已停止支援，冇修補"$'\n' ;;
                        stale)  NODE_BAD+="$desc：升級咗但進程未重啟，運行緊舊版"$'\n' ;;
                        noperm) SITE_UNKNOWN+="$label → port $port → PID $pid（無權限讀取，需要 sudo）"$'\n' ;;
                        other)  SITE_UNKNOWN+="$label → port $port → $PN_NAME（PID $pid，唔係 Node.js）"$'\n' ;;
                        *)      SITE_UNKNOWN+="$desc：版本唔喺公告範圍，請自行確認"$'\n' ;;
                    esac
                done
                unset seen
            done
            [ "$handled" = 0 ] && STATIC_SITES+="$label、"
        done

        if [ -n "$PHP_BAD" ]; then
            alert "$(count_lines "$PHP_BAD") 個網站經未修補／已停止支援嘅 PHP 處理請求（受 CVE-2026-109618／109619 影響）："
            printf '%s' "$PHP_BAD" | detail 999
            [ "$NO_PHP_FILES" -gt 0 ] && hint "其中 $NO_PHP_FILES 個網站目錄冇 PHP 檔，但 nginx 仍然會將 .php 請求交畀 PHP-FPM；刪走呢啲 PHP location 可以減少暴露"
        fi
        if [ -n "$DIRECT_BAD" ]; then
            alert "直接用伺服器 IP 連入（繞過 Cloudflare）會去到未修補嘅 PHP："
            printf '%s' "$DIRECT_BAD" | detail 999
            hint "建議喺 Forge 刪除呢個預設網站，或者改為 return 444；同時將防火牆（例如 AWS security group）嘅 80／443 限制為只接受 Cloudflare IP"
        fi
        if [ -n "$NODE_BAD" ]; then
            alert "$(count_lines "$NODE_BAD") 個網站經未修補／已停止支援嘅 Node.js 處理請求："
            printf '%s' "$NODE_BAD" | detail 999
        fi
        if [ -n "$PHP_GOOD$NODE_GOOD" ]; then
            ok "以下網站用緊已修補嘅版本："
            printf '%s%s' "$PHP_GOOD" "$NODE_GOOD" | detail 999
        fi
        if [ -n "$SITE_UNKNOWN" ]; then
            info "以下網站未能完全確認："
            printf '%s' "$SITE_UNKNOWN" | detail 999
        fi
        [ -n "$STATIC_SITES" ] && info "冇 PHP／Node.js 處理嘅網站（靜態檔案或者轉址）：${STATIC_SITES%、}"
        [ -z "$PHP_BAD$NODE_BAD$PHP_GOOD$NODE_GOOD$SITE_UNKNOWN$STATIC_SITES" ] && info "/etc/nginx/sites-enabled 冇網站設定"

        # 冇經 nginx 對應任何網站嘅 node 進程
        orphan=$(printf '%s\n' "$NODE_PROCS" | awk 'NF {print $1}' | while read -r pid; do
                     case "$MAPPED_PIDS" in *" $pid "*) continue ;; esac
                     echo "PID $pid | $(readlink -f "/proc/$pid/cwd" 2>/dev/null || echo '?') | $(ps -o args= -p "$pid" 2>/dev/null)"
                 done)
        if [ -n "$orphan" ]; then
            info "以下 Node.js 進程冇經 nginx 對應任何網站（可能係 worker、排程，或者直接開放 port）："
            printf '%s\n' "$orphan" | detail
        fi
    fi

    # =========================================================================
    section "2. session.upload_progress.enabled（臨時緩解，唔可以取代升級 PHP）"
    # =========================================================================
    SESSION_PATHS="/var/lib/php/sessions"
    for v in $PHP_VERSIONS; do
        fpm="/usr/sbin/php-fpm$v"

        # CLI 設定（只供參考，網頁請求唔經 CLI）
        cli="-"
        if [ -x "/usr/bin/php$v" ]; then
            cli=$("/usr/bin/php$v" -r 'echo extension_loaded("session") ? (ini_get("session.upload_progress.enabled") ? "On" : "Off") : "N/A";' 2>/dev/null)
        fi
        if [ ! -x "$fpm" ]; then
            info "PHP $v：冇 FPM（網頁唔受影響），CLI = ${cli:--}"
            continue
        fi

        # FPM 設定：用 php-fpm -i 由設定檔計出嚟（唔會連去運行中嘅 FPM）
        finfo=$("$fpm" -i 2>/dev/null)
        val=$(info_get "$finfo" 'session\.upload_progress\.enabled')
        src="php-fpm -i"
        if [ -z "$val" ]; then
            # 後備方法：直接讀 ini（conf.d 喺 php.ini 之後載入，以最後一個為準；冇設定即 PHP 預設 On）
            line=$(grep -hiE '^[[:space:]]*session\.upload_progress\.enabled[[:space:]]*=' \
                "/etc/php/$v/fpm/php.ini" /etc/php/$v/fpm/conf.d/*.ini 2>/dev/null | tail -n1)
            if [ -n "$line" ]; then val=$(norm_bool "${line#*=}"); else val="On"; fi
            src="ini 設定檔"
        fi
        val=$(norm_bool "$val")

        # 記低 session.save_path，3-2 會用嚟檢查 session 檔
        sp=$(info_get "$finfo" 'session\.save_path')
        case "$sp" in ""|no) ;; *) SESSION_PATHS="$SESSION_PATHS ${sp##*;}" ;; esac

        # 逐個 pool 計實際生效值（pool 入面嘅 php_value/php_admin_value 會覆寫 php.ini）
        exposed=""; pool_count=0
        for pf in /etc/php/$v/fpm/pool.d/*.conf; do
            [ -f "$pf" ] || continue
            pool_count=$((pool_count + 1))
            ov=$(grep -iE '^[[:space:]]*php_(admin_)?(value|flag)\[session\.upload_progress\.enabled\]' "$pf" 2>/dev/null | tail -n1)
            if [ -n "$ov" ]; then pv=$(norm_bool "${ov#*=}"); note="(pool 覆寫)"; else pv="$val"; note=""; fi
            [ "$pv" = "On" ] && exposed="$exposed $(basename "$pf")$note"
        done
        [ "$pool_count" = 0 ] && [ "$val" = "On" ] && exposed=" php.ini"

        running=0; fpm_running "$v" && running=1
        if [ -z "$exposed" ]; then
            ok "PHP $v FPM：Off（php.ini = $val，來源：$src；CLI = $cli）"
        else
            msg="PHP $v FPM：On —— 受影響：${exposed# }（CLI = $cli）"
            if [ "$running" = 1 ]; then
                warn "$msg；建議喺 /etc/php/$v/fpm/php.ini 設 session.upload_progress.enabled = Off 然後 reload FPM（官方：只係部分緩解，升級 PHP 先係完整修補；修補後亦建議保持 Off）"
            else
                info "$msg（FPM 冇運行）"
            fi
        fi

        # 檢查設定檔改完之後 FPM 有冇重新載入
        if [ "$running" = 1 ]; then
            read -r loaded evidence <<< "$(fpm_loaded_time "$v")"
            newest=$(stat -L -c %Y "/etc/php/$v/fpm/php.ini" /etc/php/$v/fpm/conf.d/*.ini /etc/php/$v/fpm/pool.d/*.conf 2>/dev/null | sort -n | tail -n1)
            if [ -n "$newest" ] && [ "$newest" -gt "$loaded" ]; then
                if [ "$evidence" = 1 ]; then
                    warn "PHP $v：設定檔喺 $(fmt_ts "$newest") 修改過，但 FPM 最後載入時間係 $(fmt_ts "$loaded")，新設定未生效（需要喺 Forge 重啟 PHP，或者 reload FPM）"
                else
                    info "PHP $v：設定檔修改時間 $(fmt_ts "$newest") 晚過 FPM 啟動時間 $(fmt_ts "$loaded")；如果改完已經 reload 可以忽略，否則新設定未生效"
                fi
            elif [ -n "$newest" ] && [ "$evidence" = 1 ] && [ $((NOW - newest)) -lt "$WINDOW" ]; then
                ok "PHP $v：設定檔喺 $(fmt_ts "$newest") 修改，FPM 喺 $(fmt_ts "$loaded") 重新載入，新設定已生效"
            fi
        fi
    done

    # 其他可能覆寫設定嘅地方：.user.ini / 網站自帶 php.ini / nginx PHP_VALUE
    extra=$(find /home/forge -xdev \( -name node_modules -o -name vendor -o -name .git \) -prune -o \
                -type f \( -name '.user.ini' -o -name 'php.ini' \) -print 2>/dev/null | head -n 500 \
            | xargs -r -d '\n' grep -HiE 'session\.upload_progress\.enabled' 2>/dev/null)
    extra_ng=$(grep -rHiE 'PHP_(ADMIN_)?VALUE.*upload_progress' /etc/nginx 2>/dev/null)
    if [ -n "$extra$extra_ng" ]; then
        info "以下位置亦有設定 session.upload_progress（請確認係 Off）："
        printf '%s\n%s\n' "$extra" "$extra_ng" | detail
    fi

    # =========================================================================
    section "3-1. 攻擊跡象：PHP 進程有冇開出可疑子進程"
    # =========================================================================
    PS_OUT=$(ps -eo pid=,ppid=,user=,etimes=,comm=,args= 2>/dev/null)

    # 逐個可疑名稱嘅進程向上追溯父進程，睇下係咪由 php-fpm 或 php CLI 衍生
    TREE=$(printf '%s\n' "$PS_OUT" | awk '
        BEGIN { susp = "^((ba|da|z|k|c|tc|a|fi)?sh|busybox|curl|wget|nc|ncat|netcat|socat|telnet|python[0-9.]*|perl|ruby|lua|php[0-9.]*|base64|openssl|nohup|xmrig|kinsing|kdevtmpfsi)$" }
        NF >= 5 {
            p = $1; pp[p] = $2; u[p] = $3; et[p] = $4; c[p] = $5
            a = $0; sub(/^[ \t]*[^ \t]+[ \t]+[^ \t]+[ \t]+[^ \t]+[ \t]+[^ \t]+[ \t]+[^ \t]+[ \t]*/, "", a)
            args[p] = a; ord[++n] = p
        }
        END {
            for (i = 1; i <= n; i++) {
                p = ord[i]
                if (c[p] !~ susp) continue
                lvl = ""; chain = c[p]; q = pp[p]; d = 0
                while ((q in c) && q > 1 && d < 20) {
                    chain = c[q] "(" q ") > " chain
                    if (c[q] ~ /^php-fpm/) { lvl = "FPM"; break }
                    if (lvl == "" && c[q] ~ /^php[0-9.]*$/) lvl = "CLI"
                    q = pp[q]; d++
                }
                if (lvl == "") continue
                printf "%s\t%s\t%s\t%s\t%s\t%s\n", lvl, p, u[p], et[p], chain, args[p]
            }
        }')
    fmt_tree() { awk -F'\t' '{ printf "PID %s | 用戶 %s | 已運行 %s 秒 | %s | 指令：%s\n", $2, $3, $4, $5, $6 }'; }

    fpm_all=$(printf '%s\n' "$TREE" | awk -F'\t' '$1 == "FPM"')
    fpm_kids=$(printf '%s\n' "$fpm_all" | grep -v sendmail)
    fpm_mail=$(printf '%s\n' "$fpm_all" | grep sendmail)
    cli_kids=$(printf '%s\n' "$TREE" | awk -F'\t' '$1 == "CLI"')

    if [ -n "$fpm_kids" ]; then
        alert "PHP-FPM 衍生咗 $(count_lines "$fpm_kids") 個可疑子進程（網頁請求唔應該開 shell／下載工具）"
        printf '%s\n' "$fpm_kids" | fmt_tree | detail
    else
        ok "冇發現 PHP-FPM 衍生可疑子進程（呢個係即時快照）"
    fi
    if [ -n "$fpm_mail" ]; then
        info "PHP-FPM 正透過 sh 呼叫 sendmail（PHP mail() 嘅正常行為）："
        printf '%s\n' "$fpm_mail" | fmt_tree | detail
    fi
    if [ -n "$cli_kids" ]; then
        info "PHP CLI（排程／隊列 worker）衍生咗 $(count_lines "$cli_kids") 個子進程，通常屬正常，請人手核對："
        printf '%s\n' "$cli_kids" | fmt_tree | detail
    fi

    # 喺暫存目錄執行嘅進程
    tmp_procs=$(printf '%s\n' "$PS_OUT" | awk '{ a = $0; sub(/^[ \t]*[^ \t]+[ \t]+[^ \t]+[ \t]+[^ \t]+[ \t]+[^ \t]+[ \t]+[^ \t]+[ \t]*/, "", a) }
        a ~ /(^|[ =])(\/tmp|\/var\/tmp|\/dev\/shm)\// { print "PID " $1 " | 用戶 " $3 " | " a }')
    if [ -n "$tmp_procs" ]; then
        warn "有進程喺 /tmp、/var/tmp 或 /dev/shm 執行："
        printf '%s\n' "$tmp_procs" | detail
    else
        ok "冇進程由暫存目錄執行"
    fi

    # 執行檔已被刪除或喺暫存目錄（常見於無檔案惡意程式）；冇 root 只睇到自己嘅進程
    del_exe=$(for p in /proc/[0-9]*; do
                  e=$(readlink "$p/exe" 2>/dev/null) || continue
                  case "$e" in
                      /usr/*|/bin/*|/sbin/*|/lib*|/opt/*|/snap/*) ;;
                      /tmp/*|/var/tmp/*|/dev/shm/*|*"(deleted)"*) echo "PID ${p#/proc/} → $e" ;;
                  esac
              done)
    if [ -n "$del_exe" ]; then
        alert "有進程嘅執行檔已被刪除或位於暫存目錄："
        printf '%s\n' "$del_exe" | detail
    fi

    # 挖礦程式常見名稱
    miners=$(printf '%s\n' "$PS_OUT" | awk '$5 ~ /^(xmrig|kinsing|kdevtmpfsi|minerd|cpuminer|xmr)/')
    if [ -n "$miners" ]; then
        alert "發現疑似挖礦程式："
        printf '%s\n' "$miners" | detail
    fi

    # shell／nc／python 等有對外 TCP 連線（疑似 reverse shell）
    if command -v ss >/dev/null 2>&1; then
        rshell=$(ss -tnp 2>/dev/null | grep -E 'users:\(\("((ba|da|z|k)?sh|nc|ncat|netcat|socat|telnet|python[0-9.]*|perl|ruby)"')
        if [ -n "$rshell" ]; then
            alert "有 shell／nc／python 等進程持有 TCP 連線（疑似 reverse shell）："
            printf '%s\n' "$rshell" | detail
        else
            ok "冇發現 shell 類進程持有 TCP 連線"
        fi
    fi

    # 持久化：crontab
    cron_forge=$(crontab -l 2>/dev/null | grep -vE '^[[:space:]]*(#|$)')
    cron_susp=$(printf '%s\n' "$cron_forge" | grep -iE 'curl|wget|base64|/tmp/|/dev/shm|/var/tmp|(^|[^a-z])nc[[:space:]]|bash -i|python|perl')
    if [ -n "$cron_susp" ]; then
        warn "$(id -un) 嘅 crontab 有可疑指令（請確認係咪自己設定）："
        printf '%s\n' "$cron_susp" | detail
    fi
    cron_new=$(find /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly /etc/crontab \
                   -maxdepth 1 -type f -mtime -"$DAYS" 2>/dev/null)
    if [ -n "$cron_new" ]; then
        warn "以下系統排程檔喺最近 ${DAYS} 日內有修改："
        printf '%s\n' "$cron_new" | detail
    fi

    # =========================================================================
    section "3-2. 攻擊跡象：Access log（multipart／PHP_SESSION_UPLOAD_PROGRESS／LFI）"
    # =========================================================================
    off_sites=$(grep -lsE '^[[:space:]]*access_log[[:space:]]+off' /etc/nginx/sites-enabled/* 2>/dev/null \
                | xargs -r -n1 basename | tr '\n' ' ')
    [ -n "$off_sites" ] && info "以下網站設定咗 access_log off（Forge 預設），佢哋嘅請求唔會出現喺 access log：$off_sites"
    info "Nginx 預設 log 格式唔記錄 Content-Type 同 POST 內容，multipart 上傳只能間接判斷（POST 到 .php、大量 POST 等）"

    LOGS=(); UNREADABLE=()
    while IFS= read -r f; do
        [ -z "$f" ] && continue
        if [ -r "$f" ] || [ "$SUDO_OK" = 1 ]; then LOGS+=("$f"); else UNREADABLE+=("$f"); fi
    done < <(find /var/log/nginx /var/log/apache2 -maxdepth 1 -type f -name '*access*' -mtime -$((DAYS + 1)) 2>/dev/null | sort)

    [ "${#UNREADABLE[@]}" -gt 0 ] && skip "${#UNREADABLE[@]} 個 access log 無權限讀取（需要 sudo，或將 $(id -un) 加入 adm 群組）"

    if [ "${#LOGS[@]}" -eq 0 ]; then
        info "冇可以分析嘅 access log"
    else
        LOG_SCAN=$(for f in "${LOGS[@]}"; do
                       if [ -r "$f" ]; then zcat -f -- "$f"; else priv zcat -f -- "$f"; fi
                   done 2>/dev/null | awk '
            function ip2n(ip,   p) { if (split(ip, p, ".") != 4) return -1; return ((p[1] * 256 + p[2]) * 256 + p[3]) * 256 + p[4] }
            function is_cf(ip,   n, i) { n = ip2n(ip); for (i = 1; i <= ncf; i++) if (n >= cfs[i] && n <= cfe[i]) return 1; return 0 }
            BEGIN {
                # Cloudflare IPv4 範圍（https://www.cloudflare.com/ips-v4）
                nr = split("173.245.48.0/20 103.21.244.0/22 103.22.200.0/22 103.31.4.0/22 141.101.64.0/18 108.162.192.0/18 190.93.240.0/20 188.114.96.0/20 197.234.240.0/22 198.41.128.0/17 162.158.0.0/15 104.16.0.0/13 104.24.0.0/14 172.64.0.0/13 131.0.72.0/22", r, " ")
                for (i = 1; i <= nr; i++) { split(r[i], cq, "/"); ncf++; cfs[ncf] = ip2n(cq[1]); cfe[ncf] = cfs[ncf] + 2 ^ (32 - cq[2]) - 1 }
            }
            {
                line = $0; l = tolower(line)
                st = "-"; if (match(line, /" [0-9][0-9][0-9] /)) st = substr(line, RSTART + 2, 3)
                m = ""; path = ""
                if (match(line, /"[A-Z]+ [^ "]+/)) {
                    req = substr(line, RSTART + 1, RLENGTH - 1)
                    sp = index(req, " "); m = substr(req, 1, sp - 1); path = substr(req, sp + 1)
                    q = index(path, "?"); if (q > 0) path = substr(path, 1, q - 1)
                }
                lpath = tolower(path)
                if (index(l, "upload_progress")) print "UP\t" st "\t" line
                if (l ~ /sess_[a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9]|\/var\/lib\/php|php:\/\/|phar:\/\/|data:\/\/|expect:\/\/|zip:\/\/|\.\.\/|\.\.%2f|%2e%2e|\/etc\/passwd|\/proc\/self/)
                    print "LFI\t" st "\t" line
                if (index(l, "multipart")) print "MP\t" st "\t" line
                isphp = (lpath ~ /\.(php[0-9]?|phtml|phar|pht|phps)$/ && lpath !~ /(^|\/)index\.php$/)
                if (m == "POST") { post[$1]++; if (isphp) print "POSTPHP\t" st "\t" path }
                else if (isphp && st ~ /^2/) print "GETPHP\t" st "\t" path
                # 統計來源 IP 有幾多係 Cloudflare（即係 nginx 冇還原真實訪客 IP）
                if ($1 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) { ipn++; if (!($1 in cfc)) cfc[$1] = is_cf($1); if (cfc[$1]) cfn++ }
            }
            END {
                print "TOTAL\t" NR; print "CF\t" cfn + 0 "\t" ipn + 0
                for (ip in post) print "POSTIP\t" post[ip] "\t" ip "\t" ((ip in cfc) && cfc[ip] ? "Cloudflare" : "")
            }')
        tagged() { printf '%s\n' "$LOG_SCAN" | awk -F'\t' -v t="$1" '$1 == t'; }

        info "已分析 ${#LOGS[@]} 個 log 檔，共 $(tagged TOTAL | cut -f2) 行"

        # 來源 IP 大部分係 Cloudflare：nginx 冇還原真實訪客 IP
        cf_n=$(tagged CF | cut -f2); ip_n=$(tagged CF | cut -f3)
        if [ "${ip_n:-0}" -gt 0 ] && [ $(( ${cf_n:-0} * 2 )) -gt "$ip_n" ]; then
            if grep -rqsiE '^[[:space:]]*real_ip_header[[:space:]]+(CF-Connecting-IP|X-Forwarded-For)' /etc/nginx; then
                info "log 入面 $(( cf_n * 100 / ip_n ))% 嘅請求來自 Cloudflare IP（nginx 已設定 real_ip_header）"
            else
                warn "log 入面 $(( cf_n * 100 / ip_n ))% 嘅請求來源係 Cloudflare IP：nginx 未設定還原真實訪客 IP，出事時追查唔到攻擊來源"
                hint "喺 nginx http 區塊加 set_real_ip_from <Cloudflare IP 範圍>; 同 real_ip_header CF-Connecting-IP;（範圍：https://www.cloudflare.com/ips/）"
            fi
        fi

        # (a) PHP_SESSION_UPLOAD_PROGRESS
        up=$(tagged UP | cut -f3-)
        if [ -n "$up" ]; then
            alert "發現 $(count_lines "$up") 個包含 PHP_SESSION_UPLOAD_PROGRESS／upload_progress 嘅請求："
            printf '%s\n' "$up" | detail
        else
            ok "冇發現包含 PHP_SESSION_UPLOAD_PROGRESS 嘅請求（注意：POST body 入面嘅欄位唔會出現喺 log）"
        fi

        # (b) multipart（只有自訂 log 格式記錄 Content-Type 先會有）
        mp=$(tagged MP | cut -f3-)
        if [ -n "$mp" ]; then
            warn "發現 $(count_lines "$mp") 個 multipart 相關請求："
            printf '%s\n' "$mp" | detail
        fi

        # (c) LFI／session 檔包含（session upload progress 攻擊通常配合 LFI 使用）
        lfi_ok=$(tagged LFI | awk -F'\t' '$2 ~ /^2/' | cut -f3-)
        lfi_all=$(tagged LFI)
        if [ -n "$lfi_ok" ]; then
            alert "發現 $(count_lines "$lfi_ok") 個疑似 LFI／包含 session 檔嘅請求「成功」回應 2xx："
            printf '%s\n' "$lfi_ok" | detail
        elif [ -n "$lfi_all" ]; then
            info "有 $(count_lines "$lfi_all") 個疑似 LFI 探測請求，但全部非 2xx（多數係自動掃描器）"
        else
            ok "冇發現 LFI／session 檔包含嘅請求"
        fi

        # (d) POST 到 index.php 以外嘅 PHP 檔（Laravel 正常只會經 index.php）
        postphp=$(tagged POSTPHP)
        postphp_ok=$(printf '%s\n' "$postphp" | awk -F'\t' '$2 ~ /^2/')
        if [ -n "$postphp_ok" ]; then
            warn "有 POST 請求成功（2xx）送到 index.php 以外嘅 PHP 檔，可能係 webshell（WordPress 等非 Laravel 網站可能屬正常）："
            printf '%s\n' "$postphp_ok" | awk -F'\t' '{print $2 " " $3}' | sort | uniq -c | sort -rn | detail
        elif [ -n "$postphp" ]; then
            info "有 $(count_lines "$postphp") 個 POST 到其他 PHP 檔嘅請求，全部非 2xx（多數係掃描器）"
        else
            ok "冇 POST 到 index.php 以外嘅 PHP 檔"
        fi

        # (e) GET 其他 PHP 檔並成功回應
        getphp=$(tagged GETPHP)
        if [ -n "$getphp" ]; then
            warn "有請求成功存取 index.php 以外嘅 PHP 檔（Laravel 網站唔應該出現）："
            printf '%s\n' "$getphp" | awk -F'\t' '{print $2 " " $3}' | sort | uniq -c | sort -rn | detail
        fi

        # (f) POST 次數最多嘅 IP
        postip=$(tagged POSTIP | sort -t "$(printf '\t')" -k2,2nr | head -n 10)
        if [ -n "$postip" ]; then
            info "POST 請求最多嘅 IP（前 10 名，供參考）："
            printf '%s\n' "$postip" | awk -F'\t' '{printf "%8s 次  %s%s\n", $2, $3, ($4 != "" ? "（" $4 "）" : "")}' | detail
        fi
    fi

    # Laravel log 入面嘅相關痕跡
    lv_logs=$(find /home/forge -maxdepth 6 -path '*/storage/logs/*' -type f -name '*.log' -mtime -"$DAYS" 2>/dev/null)
    if [ -n "$lv_logs" ]; then
        lv_hits=$(printf '%s\n' "$lv_logs" | xargs -r -d '\n' grep -HaiE \
            'php_session_upload_progress|upload_progress_|php://filter|/var/lib/php/sessions/sess_|/tmp/sess_' 2>/dev/null)
        if [ -n "$lv_hits" ]; then
            warn "Laravel log 入面有 upload_progress／session 檔包含相關記錄："
            printf '%s\n' "$lv_hits" | detail
        else
            ok "Laravel log（$(count_lines "$lv_logs") 個）冇相關記錄"
        fi
    fi

    # PHP session 檔入面有冇 upload_progress_ 資料（Laravel 唔用原生 session，正常唔應該有）
    for sp in $(printf '%s\n' $SESSION_PATHS /tmp | sort -u); do
        [ -d "$sp" ] || continue
        if { [ -r "$sp" ] && [ -x "$sp" ]; } || [ "$HAS_PRIV" = 1 ]; then
            s_hits=$(priv find "$sp" -maxdepth 1 -type f -name 'sess_*' -exec grep -lasF 'upload_progress_' {} + 2>/dev/null)
            s_recent=$(priv find "$sp" -maxdepth 1 -type f -name 'sess_*' -mtime -"$DAYS" 2>/dev/null | grep -c .)
            if [ -n "$s_hits" ]; then
                alert "$sp 入面有 session 檔包含 upload_progress_ 資料（強烈攻擊跡象）："
                printf '%s\n' "$s_hits" | detail
            elif [ "$s_recent" -gt 0 ]; then
                info "$sp：最近 ${DAYS} 日有 $s_recent 個 sess_ 檔，但冇 upload_progress_ 資料（upload progress 資料完成後會被清走，唔代表一定冇被攻擊）"
            else
                ok "$sp：冇可疑 session 檔"
            fi
        else
            skip "$sp 無權限列出（需要 sudo）"
        fi
    done

    # =========================================================================
    section "3-3. 攻擊跡象：Web 目錄最近 ${DAYS} 日新增／修改嘅 PHP 檔"
    # =========================================================================
    ROOTS=""
    for d in /home/forge /var/www; do [ -d "$d" ] && ROOTS="$ROOTS $d"; done

    # Webshell 常見特徵
    SIG='eval[[:space:]]*\([[:space:]]*(base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|rawurldecode|\$_(POST|GET|REQUEST|COOKIE|SERVER))|assert[[:space:]]*\([[:space:]]*\$_|(system|shell_exec|passthru|exec|popen|proc_open|pcntl_exec)[[:space:]]*\([[:space:]]*\$_(POST|GET|REQUEST|COOKIE|SERVER)|base64_decode[[:space:]]*\([[:space:]]*\$_|\$_(POST|GET|REQUEST|COOKIE)\[[^]]{0,40}\][[:space:]]*\(|create_function[[:space:]]*\(|FilesMan|b374k|c99shell|r57shell|weevely'

    if [ -z "$ROOTS" ]; then
        skip "搵唔到 /home/forge 或 /var/www"
    else
        # mtime 或 ctime 喺範圍內都計（攻擊者可以改 mtime，但改唔到 ctime）
        RECENT=$(find $ROOTS -xdev \( -name node_modules -o -name .git -o -name .npm -o -name .cache \) -prune -o \
                    -type f "${PHP_EXT[@]}" \( -mtime -"$DAYS" -o -ctime -"$DAYS" \) \
                    -printf '%TY-%Tm-%Td %TH:%TM\t%u\t%s\t%p\n' 2>/dev/null | sort -r)
        CLASSIFIED=$(printf '%s\n' "$RECENT" | awk -F'\t' 'NF >= 4 {
                p = tolower($4)
                if (p ~ /\/vendor\//) c = "VENDOR"
                else if (p ~ /\/storage\/framework\/(views|cache)\// || p ~ /\/bootstrap\/cache\//) c = "CACHE"
                else if (p ~ /\/public\/index\.php$/) c = "NORMAL"
                else if (p ~ /\/(public|storage|uploads?|tmp|temp|\.well-known)\// || p ~ /\/\.[^\/]+$/) c = "HIGH"
                else c = "NORMAL"
                print c "\t" $0 }')
        by_cat() { printf '%s\n' "$CLASSIFIED" | awk -F'\t' -v c="$1" '$1 == c { printf "%s | %s | %s bytes | %s\n", $2, $3, $4, $5 }'; }

        # (a) 特徵碼掃描（所有最近改動嘅 PHP 檔）
        sig_hits=$(printf '%s\n' "$CLASSIFIED" | awk -F'\t' 'NF >= 5 {print $5}' \
                   | xargs -r -d '\n' grep -lisE -- "$SIG" 2>/dev/null)
        if [ -n "$sig_hits" ]; then
            alert "$(count_lines "$sig_hits") 個最近改動嘅 PHP 檔含有 webshell 特徵："
            printf '%s\n' "$sig_hits" | detail
        else
            ok "最近改動嘅 PHP 檔冇發現常見 webshell 特徵"
        fi

        # (b) 高風險位置
        high=$(by_cat HIGH)
        if [ -n "$high" ]; then
            warn "$(count_lines "$high") 個 PHP 檔喺高風險位置（public／storage／uploads／隱藏檔）有改動："
            printf '%s\n' "$high" | detail
        else
            ok "高風險位置冇新增／修改嘅 PHP 檔"
        fi

        # (c) 一般程式碼（多數係部署造成）
        normal=$(by_cat NORMAL)
        if [ -n "$normal" ]; then
            info "$(count_lines "$normal") 個一般程式碼 PHP 檔有改動（如最近有部署屬正常，請對照部署時間）："
            printf '%s\n' "$normal" | detail
        fi
        info "vendor 目錄有 $(by_cat VENDOR | grep -c .) 個、編譯快取（views/cache）有 $(by_cat CACHE | grep -c .) 個 PHP 檔有改動（已納入特徵碼掃描）"
    fi

    # Laravel 網站：public/ 只應該有 index.php；storage/app（上傳目錄）唔應該有 PHP 檔（不限日期）
    for site in /home/forge/*/; do
        for base in "$site" "${site}current/"; do
            [ -f "${base}artisan" ] || continue
            pub=$(find "${base}public" -xdev -type f "${PHP_EXT[@]}" ! -path "${base}public/index.php" 2>/dev/null)
            if [ -n "$pub" ]; then
                warn "Laravel 網站 ${base}public 有 index.php 以外嘅 PHP 檔（不限日期）："
                printf '%s\n' "$pub" | detail
            fi
            upl=$(find "${base}storage/app" -xdev -type f "${PHP_EXT[@]}" 2>/dev/null)
            if [ -n "$upl" ]; then
                alert "Laravel 網站 ${base}storage/app（上傳目錄）入面有 PHP 檔："
                printf '%s\n' "$upl" | detail
            fi
        done
    done

    # 暫存目錄入面最近嘅 PHP 檔或可執行檔
    tmp_files=$(find /tmp /var/tmp /dev/shm -xdev -type f \( "${PHP_EXT[@]}" -o -perm -u=x \) -mtime -"$DAYS" \
                    -printf '%TY-%Tm-%Td %TH:%TM | %u | %p\n' 2>/dev/null)
    if [ -n "$tmp_files" ]; then
        warn "暫存目錄有最近建立嘅 PHP 檔或可執行檔："
        printf '%s\n' "$tmp_files" | detail
    else
        ok "暫存目錄冇最近建立嘅 PHP 檔或可執行檔"
    fi

    # =========================================================================
    section "3-4. 攻擊跡象：可疑系統用戶"
    # =========================================================================
    EXPECTED_USERS="root forge"

    # (a) root 以外嘅 UID 0 帳戶
    uid0=$(awk -F: '$3 == 0 && $1 != "root" {print $1}' /etc/passwd | tr '\n' ' ')
    if [ -n "$uid0" ]; then alert "發現 root 以外嘅 UID 0 帳戶：$uid0"; else ok "只有 root 係 UID 0"; fi

    # (b) 可登入帳戶（有正常 shell）
    while IFS=: read -r u uid home shell; do
        [ -z "$u" ] && continue
        bt="未知"; recent_home=0
        b=$(stat -c %W "$home" 2>/dev/null)
        case "$b" in ''|*[!0-9]*|0) ;; *) bt=$(fmt_ts "$b"); [ $((NOW - b)) -lt "$WINDOW" ] && recent_home=1 ;; esac
        desc="$u（UID $uid，家目錄 $home，shell $shell，家目錄建立於 $bt）"
        if [ -n "$CLOUD_USER" ] && [ "$u" = "$CLOUD_USER" ]; then
            info "雲端平台預設用戶（cloud-init 建立${CLOUD_NAME:+，$CLOUD_NAME}）：$desc；請確認佢嘅 SSH key 只有你自己嘅"
            continue
        fi
        case " $EXPECTED_USERS " in
            *" $u "*) info "可登入帳戶：$desc" ;;
            *)
                if [ "$recent_home" = 1 ]; then
                    warn "最近 ${DAYS} 日內新建嘅可登入帳戶：$desc"
                else
                    warn "非預期嘅可登入帳戶：$desc（如係 Forge 網站隔離用戶可以忽略）"
                fi ;;
        esac
    done < <(awk -F: '$7 != "" && $7 !~ /(nologin|false|sync|halt|shutdown)$/ {print $1 ":" $3 ":" $6 ":" $7}' /etc/passwd)

    # (c) sudo／admin／wheel 群組成員
    for g in sudo admin wheel; do
        mem=$(getent group "$g" 2>/dev/null | cut -d: -f4)
        [ -z "$mem" ] && continue
        info "$g 群組成員：$mem"
        for m in $(printf '%s' "$mem" | tr ',' ' '); do
            if [ -n "$CLOUD_USER" ] && [ "$m" = "$CLOUD_USER" ]; then
                info "$g 群組包括雲端平台預設用戶 $m（正常，但請確認佢嘅 SSH key）"
                continue
            fi
            case " $EXPECTED_USERS " in *" $m "*) ;; *) alert "$g 群組有非預期成員：$m" ;; esac
        done
    done

    # (d) 帳戶相關檔案最近有冇修改
    acct_changed=""
    for f in /etc/passwd /etc/shadow /etc/group /etc/gshadow /etc/sudoers; do
        m=$(stat -c %Y "$f" 2>/dev/null) || continue
        [ $((NOW - m)) -lt "$WINDOW" ] && acct_changed="$acct_changed$f（$(fmt_ts "$m")）"$'\n'
    done
    sudoers_d=$(find /etc/sudoers.d -type f -mtime -"$DAYS" 2>/dev/null)
    [ -n "$sudoers_d" ] && acct_changed="$acct_changed$sudoers_d"$'\n'
    if [ -n "$acct_changed" ]; then
        warn "以下帳戶／權限檔喺最近 ${DAYS} 日內有修改（安裝套件亦可能會改，請核對）："
        printf '%s' "$acct_changed" | detail
    else
        ok "帳戶相關檔案（passwd／shadow／group／sudoers）最近 ${DAYS} 日冇修改"
    fi

    # (e) 系統 log 入面嘅新增／修改帳戶記錄
    ua_log=""; ua_src=""
    auth_files=$(find /var/log -maxdepth 1 -name 'auth.log*' -mtime -$((DAYS + 1)) 2>/dev/null | sort)
    if [ -n "$auth_files" ] && { [ -r /var/log/auth.log ] || [ "$SUDO_OK" = 1 ]; }; then
        ua_log=$(for f in $auth_files; do priv zcat -f -- "$f" 2>/dev/null; done \
                 | grep -aE 'useradd|usermod|groupadd|userdel|new user|new group|add .* to group|password changed')
        ua_src="auth.log"
    elif command -v journalctl >/dev/null 2>&1; then
        ua_log=$(journalctl -q --no-pager --since "$DAYS days ago" \
                     SYSLOG_IDENTIFIER=useradd SYSLOG_IDENTIFIER=usermod SYSLOG_IDENTIFIER=groupadd \
                     SYSLOG_IDENTIFIER=userdel SYSLOG_IDENTIFIER=passwd SYSLOG_IDENTIFIER=chpasswd 2>/dev/null)
        ua_src="journalctl"
    fi
    if [ -n "$ua_log" ]; then
        warn "系統 log（$ua_src）有新增／修改帳戶嘅記錄："
        printf '%s\n' "$ua_log" | detail
    elif [ -n "$ua_src" ]; then
        ok "系統 log（$ua_src）最近 ${DAYS} 日冇新增／修改帳戶記錄"
    else
        skip "無權限讀取 auth.log／journal"
    fi

    # (f) SSH authorized_keys
    for home in $(awk -F: '$7 != "" && $7 !~ /(nologin|false|sync|halt|shutdown)$/ {print $6}' /etc/passwd | sort -u); do
        f="$home/.ssh/authorized_keys"
        m=$(priv stat -c %Y "$f" 2>/dev/null)
        if [ -z "$m" ]; then
            # 其他用戶嘅 .ssh 目錄冇 sudo 讀唔到（例如 root、雲端預設用戶）
            [ "$HAS_PRIV" = 0 ] && [ "$home" != "$HOME" ] && [ -d "$home" ] && skip "無權限讀取 $f（需要 sudo）"
            continue
        fi
        cnt=$(priv grep -cvE '^[[:space:]]*(#|$)' "$f" 2>/dev/null)
        msg="$f：${cnt:-0} 條 key，最後修改 $(fmt_ts "$m")"
        if [ $((NOW - m)) -lt "$WINDOW" ]; then warn "$msg（最近 ${DAYS} 日內有改動，請核對每條 key）"; else info "$msg"; fi
        priv ssh-keygen -lf "$f" 2>/dev/null | detail
    done

    # (g) 最近登入記錄
    logins=$(last -i -n 15 2>/dev/null | grep -vE '^(wtmp|$)')
    if [ -n "$logins" ]; then
        info "最近 15 次登入（請確認 IP 係咪自己或 Forge）："
        printf '%s\n' "$logins" | detail
    fi

    # =========================================================================
    section "檢查摘要"
    # =========================================================================
    if [ "$ALERTS" = 0 ] && [ "$WARNS" = 0 ]; then
        ok "冇發現需要處理嘅項目"
    else
        printf '  警告 %s%d%s 項，注意 %s%d%s 項：\n' "$C_RED" "$ALERTS" "$C_RST" "$C_YEL" "$WARNS" "$C_RST"
        for f in "${FINDINGS[@]}"; do printf '   • %s\n' "$f"; done
    fi
    # 畀本機解析用（唔會顯示）
    printf '##RESULT##|%d|%d\n' "$ALERTS" "$WARNS"
}

main "$@" < /dev/null
REMOTE_EOF
}

# =============================================================================
# 本機部分
# =============================================================================

# -P：只印出遠端腳本
if [ "$PRINT_REMOTE" = 1 ]; then
    remote_script
    exit 0
fi

# 讀取遠端輸出：即時顯示，同時記錄落暫存檔；結果行另外寫入 result 檔
process_stream() {
    local result_file="$1" raw_file="$2" line
    while IFS= read -r line; do
        case "$line" in
            '##RESULT##|'*) printf '%s\n' "$line" > "$result_file" ;;
            *) printf '%s\n' "$line"; printf '%s\n' "$line" >> "$raw_file" ;;
        esac
    done
}

RUN_DIR=$(mktemp -d "${TMPDIR:-/tmp}/forge-scan.XXXXXX") || { echo "錯誤：無法建立本機暫存目錄" >&2; exit 70; }
trap 'rm -rf "$RUN_DIR"' EXIT

if [ -n "$OUT_DIR" ]; then
    mkdir -p "$OUT_DIR" || { echo "錯誤：無法建立報告目錄 $OUT_DIR" >&2; exit 73; }
fi

TOTAL=${#SERVERS[@]}
SUMMARY=()
EXIT_CODE=0
STAMP=$(date '+%Y%m%d-%H%M%S')
idx=0

printf '%sLaravel Forge 安全檢查%s（%s，共 %d 部伺服器，檢查最近 %d 日，只讀模式）\n' \
    "$L_BOLD" "$L_RST" "$(date '+%Y-%m-%d %H:%M')" "$TOTAL" "$DAYS"

for entry in "${SERVERS[@]}"; do
    idx=$((idx + 1))

    # 解析 [用戶@]主機[:port]
    user="$SSH_USER"; host="$entry"; port="$SSH_PORT"
    case "$host" in *@*) user="${host%%@*}"; host="${host#*@}" ;; esac
    case "$host" in *:*) port="${host##*:}"; host="${host%:*}" ;; esac

    printf '\n%s══════════════════════════════════════════════════════════════%s\n' "$L_BLU" "$L_RST"
    printf '%s 伺服器 %d/%d：%s@%s%s%s\n' "$L_BOLD" "$idx" "$TOTAL" "$user" "$host" "${port:+:$port}" "$L_RST"
    printf '%s══════════════════════════════════════════════════════════════%s\n' "$L_BLU" "$L_RST"

    raw="$RUN_DIR/$idx.raw"; res="$RUN_DIR/$idx.res"; err="$RUN_DIR/$idx.err"
    : > "$raw"

    # BatchMode=yes：唔會停低等輸入密碼；連唔到就直接報錯
    ssh_cmd=(ssh -o BatchMode=yes -o ConnectTimeout=10 -o ServerAliveInterval=15 -o ServerAliveCountMax=4)
    [ -n "$port" ] && ssh_cmd+=(-p "$port")
    [ -n "$SSH_KEY" ] && ssh_cmd+=(-i "$SSH_KEY" -o IdentitiesOnly=yes)
    ssh_cmd+=("$user@$host" "bash -s -- $DAYS $MAX_LINES $USE_COLOR $USE_SUDO")

    remote_script | "${ssh_cmd[@]}" 2>"$err" | process_stream "$res" "$raw"
    rc=${PIPESTATUS[1]}

    label="$user@$host${port:+:$port}"
    if [ -s "$res" ]; then
        alerts=$(cut -d'|' -f2 "$res"); warns=$(cut -d'|' -f3 "$res")
        if [ "$alerts" -gt 0 ]; then
            status="${L_RED}警告${L_RST}"; [ "$EXIT_CODE" -lt 2 ] && EXIT_CODE=2
        elif [ "$warns" -gt 0 ]; then
            status="${L_YEL}注意${L_RST}"; [ "$EXIT_CODE" -lt 1 ] && EXIT_CODE=1
        else
            status="${L_GRN}正常${L_RST}"
        fi
    else
        alerts="-"; warns="-"
        if [ "$rc" = 255 ]; then status="${L_RED}連線失敗${L_RST}"; else status="${L_RED}檢查未完成 (rc=$rc)${L_RST}"; fi
        EXIT_CODE=3
        printf '\n  %s[錯誤]%s 無法完成檢查：\n' "$L_RED" "$L_RST"
        sed 's/^/        /' "$err"
        printf '        提示：請先手動執行 ssh %s 確認可以用 key 登入（同埋已接受 host key）\n' "$user@$host"
    fi
    SUMMARY+=("$(printf '%-40s %6s %6s   %s' "$label" "$alerts" "$warns" "$status")")

    # 儲存純文字報告（去除顏色碼）
    if [ -n "$OUT_DIR" ]; then
        report="$OUT_DIR/${host}_${STAMP}.txt"
        {
            printf 'Laravel Forge 安全檢查報告\n伺服器：%s\n時間：%s\n檢查範圍：最近 %d 日\n' "$label" "$(date '+%Y-%m-%d %H:%M:%S')" "$DAYS"
            sed $'s/\033\\[[0-9;]*m//g' "$raw"
            [ -s "$err" ] && { printf '\n[SSH 錯誤輸出]\n'; cat "$err"; }
        } > "$report"
        printf '\n  報告已儲存：%s\n' "$report"
    fi
done

# ---------- 總結 ----------
printf '\n%s══════════════════════════════ 總結 ══════════════════════════════%s\n' "$L_BLU" "$L_RST"
printf '%s%-40s %6s %6s   %s%s\n' "$L_BOLD" "Server" "Alert" "Warn" "Status" "$L_RST"
for s in "${SUMMARY[@]}"; do printf '%s\n' "$s"; done
printf '\n提示：以上全部為只讀檢查，冇修改任何設定。「注意」項目需要人手判斷是否正常。\n'

exit "$EXIT_CODE"
