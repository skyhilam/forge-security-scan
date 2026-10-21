#!/usr/bin/env bash
# =============================================================================
# forge-security-scan.sh
#
# 用途：喺本機透過 SSH 掃描一部或多部 Laravel Forge 伺服器，檢查：
#   1. PHP 版本
#   2. session.upload_progress.enabled 係咪已經設為 Off
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

VERSION="1.0.0"

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
    local n=0 line
    while IFS= read -r line; do
        [ -z "$line" ] && continue
        n=$((n + 1))
        [ "$n" -le "$MAX_LINES" ] && printf '        %s%s%s\n' "$C_DIM" "${line:0:300}" "$C_RST"
    done
    [ "$n" -gt "$MAX_LINES" ] && printf '        %s…… 仲有 %d 行未顯示（可用 -n 調整）%s\n' "$C_DIM" $((n - MAX_LINES)) "$C_RST"
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

    # =========================================================================
    section "1. PHP 版本"
    # =========================================================================
    PHP_VERSIONS=$(find /etc/php -mindepth 1 -maxdepth 1 -type d -printf '%f\n' 2>/dev/null | grep -E '^[0-9]+\.[0-9]+$' | sort -V)
    if command -v php >/dev/null 2>&1; then
        info "預設 php 指令：$(php -r 'echo PHP_VERSION;' 2>/dev/null)（$(readlink -f "$(command -v php)")）"
    else
        warn "搵唔到 php 指令"
    fi
    [ -z "$PHP_VERSIONS" ] && warn "/etc/php 下面搵唔到任何已安裝嘅 PHP 版本"

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
        # 官方支援期：8.1 或以下已 EOL；8.2 安全更新至 2026-12-31
        num=$(( ${v%%.*} * 100 + ${v#*.} ))
        if [ "$num" -lt 802 ]; then
            if [ "$st" = "FPM 運行中" ]; then
                warn "$msg：已停止官方安全更新（EOL），建議升級"
            else
                info "$msg：已 EOL，但 FPM 冇運行"
            fi
        elif [ "$num" -eq 802 ]; then
            info "$msg：官方安全支援至 2026-12-31，請準備升級"
        else
            ok "$msg"
        fi
    done

    # =========================================================================
    section "2. session.upload_progress.enabled（建議設為 Off）"
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
                warn "$msg；建議喺 /etc/php/$v/fpm/php.ini 設 session.upload_progress.enabled = Off 然後 reload FPM"
            else
                info "$msg（FPM 冇運行）"
            fi
        fi

        # 檢查設定檔改完之後 FPM 有冇重新載入
        if [ "$running" = 1 ]; then
            mpid=$(fpm_master_pid "$v")
            et=$(ps -o etimes= -p "$mpid" 2>/dev/null | tr -d ' ')
            loaded=$((NOW - ${et:-0}))
            # FPM 每次 start/reload 都會喺 log 寫 "ready to handle connections"
            last_ready=$(priv tail -n 5000 "/var/log/php$v-fpm.log" 2>/dev/null \
                | grep -a 'ready to handle connections' | tail -n1 | sed -E 's/^\[([^]]+)\].*/\1/')
            if [ -n "$last_ready" ]; then
                le=$(date -d "$(printf '%s' "$last_ready" | tr '-' ' ')" +%s 2>/dev/null)
                [ -n "$le" ] && [ "$le" -gt "$loaded" ] && loaded=$le
            fi
            newest=$(stat -L -c %Y "/etc/php/$v/fpm/php.ini" /etc/php/$v/fpm/conf.d/*.ini /etc/php/$v/fpm/pool.d/*.conf 2>/dev/null | sort -n | tail -n1)
            if [ -n "$newest" ] && [ "$newest" -gt "$loaded" ]; then
                if [ -n "$last_ready" ]; then
                    warn "PHP $v：設定檔喺 $(fmt_ts "$newest") 修改過，但 FPM 最後載入時間係 $(fmt_ts "$loaded")，新設定未生效（需要 reload FPM）"
                else
                    info "PHP $v：設定檔修改時間 $(fmt_ts "$newest") 晚過 FPM 啟動時間 $(fmt_ts "$loaded")；如果改完已經 reload 可以忽略，否則新設定未生效"
                fi
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
            }
            END { print "TOTAL\t" NR; for (ip in post) print "POSTIP\t" post[ip] "\t" ip }')
        tagged() { printf '%s\n' "$LOG_SCAN" | awk -F'\t' -v t="$1" '$1 == t'; }

        info "已分析 ${#LOGS[@]} 個 log 檔，共 $(tagged TOTAL | cut -f2) 行"

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
            printf '%s\n' "$postip" | awk -F'\t' '{printf "%8s 次  %s\n", $2, $3}' | detail
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
    for home in $(awk -F: '$7 !~ /(nologin|false)$/ {print $6}' /etc/passwd | sort -u); do
        f="$home/.ssh/authorized_keys"
        m=$(priv stat -c %Y "$f" 2>/dev/null)
        if [ -z "$m" ]; then
            [ "$home" = /root ] && [ "$HAS_PRIV" = 0 ] && skip "無權限讀取 /root/.ssh/authorized_keys"
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
