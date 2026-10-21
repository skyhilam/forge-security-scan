#!/usr/bin/env bash
# =============================================================================
# 煙霧測試：喺一個「用完即棄」嘅 Ubuntu 環境（root）入面佈置假攻擊痕跡，
# 再確認 forge-security-scan.sh 全部揾得到。
#
# ⚠ 會安裝套件、建立用戶同寫入假 webshell，千祈唔好喺真伺服器執行！
#
# 本機（需要 Docker）：
#   docker run --rm -v "$PWD":/src -w /src ubuntu:24.04 bash tests/smoke-test.sh
# GitHub Actions：見 .github/workflows/ci.yml
# =============================================================================
set -euo pipefail

if [ "$(id -u)" != 0 ] || { [ ! -f /.dockerenv ] && [ "${CI:-}" != "true" ]; }; then
    echo "只可以喺 Docker container 或 CI 入面以 root 執行" >&2
    exit 1
fi

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCAN="$ROOT/forge-security-scan.sh"
PASS=0; FAIL=0

# ---------- 安裝環境 ----------
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null
apt-get install -y -qq php8.3-fpm php8.3-cli iproute2 procps >/dev/null 2>&1
id forge >/dev/null 2>&1 || useradd -m -s /bin/bash forge

# 用 -P 印出遠端腳本，直接喺本機執行（參數：日數 行數 顏色 sudo）
run_scan() { "$SCAN" -P | bash -s -- 7 20 0 1; }

expect() {      # expect <描述> <輸出> <要搵嘅字串>
    if grep -qF -- "$3" <<<"$2"; then
        echo "  PASS  $1"; PASS=$((PASS + 1))
    else
        echo "  FAIL  $1（搵唔到：$3）"; FAIL=$((FAIL + 1))
    fi
}

# ---------- 情況一：乾淨環境 ----------
mkdir -p /home/forge/site/public /home/forge/site/storage/app/public /var/lib/php/sessions /var/log/nginx
touch /home/forge/site/artisan
echo '<?php echo 1;' > /home/forge/site/public/index.php
: > /var/log/nginx/access.log
chown -R forge:forge /home/forge
php-fpm8.3 >/dev/null 2>&1

echo "== 情況一：乾淨環境（upload_progress 預設 On）=="
out=$(run_scan)
expect "偵測到 PHP 版本"                 "$out" "[正常] PHP 8.3"
expect "upload_progress 預設 On 會提示"   "$out" "PHP 8.3 FPM：On"
expect "冇 FPM 可疑子進程"               "$out" "冇發現 PHP-FPM 衍生可疑子進程"
expect "冇 webshell 特徵"                "$out" "冇發現常見 webshell 特徵"
expect "冇 UID 0 帳戶"                   "$out" "只有 root 係 UID 0"
expect "輸出結果行"                      "$out" "##RESULT##|"

# ---------- 情況二：佈置攻擊痕跡 ----------
sed -i 's/^;\?session.upload_progress.enabled.*/session.upload_progress.enabled = Off/' /etc/php/8.3/fpm/php.ini
# 假 webshell + 上傳目錄入面嘅 PHP 檔
echo '<?php eval(base64_decode($_POST["x"]));' > /home/forge/site/public/shell.php
echo '<?php' > /home/forge/site/storage/app/public/avatar.php
chown -R forge:forge /home/forge
# 假 access log
cat > /var/log/nginx/access.log <<'LOG'
1.2.3.4 - - [21/Oct/2026:10:00:00 +0000] "POST /shell.php HTTP/1.1" 200 12 "-" "curl/8.0"
5.6.7.8 - - [21/Oct/2026:10:00:01 +0000] "GET /?PHP_SESSION_UPLOAD_PROGRESS=1 HTTP/1.1" 200 12 "-" "x"
5.6.7.8 - - [21/Oct/2026:10:00:02 +0000] "GET /?f=../../../../var/lib/php/sessions/sess_abcdefgh123 HTTP/1.1" 200 1 "-" "x"
LOG
# 帶 upload_progress 資料嘅 session 檔
echo 'upload_progress_x|a:0:{}' > /var/lib/php/sessions/sess_abcdefgh123
# 假「php-fpm」進程開出 sh 子進程
cp /bin/bash /tmp/php-fpm8.3
su forge -c '/tmp/php-fpm8.3 -c "sh -c \"sleep 120; :\"; :" &'
# 可疑用戶
useradd -m -s /bin/bash -o -u 0 backdoor

sleep 1
echo "== 情況二：有攻擊痕跡（upload_progress 已設為 Off）=="
out=$(run_scan)
expect "upload_progress Off 判斷正確"     "$out" "PHP 8.3 FPM：Off"
expect "FPM 可疑子進程"                   "$out" "PHP-FPM 衍生咗 1 個可疑子進程"
expect "PHP_SESSION_UPLOAD_PROGRESS 請求" "$out" "PHP_SESSION_UPLOAD_PROGRESS／upload_progress 嘅請求"
expect "LFI 成功請求"                     "$out" "疑似 LFI／包含 session 檔嘅請求「成功」"
expect "POST 到其他 PHP 檔"               "$out" "200 /shell.php"
expect "session 檔有 upload_progress"    "$out" "包含 upload_progress_ 資料"
expect "webshell 特徵"                    "$out" "/home/forge/site/public/shell.php"
expect "上傳目錄有 PHP 檔"                "$out" "storage/app（上傳目錄）入面有 PHP 檔"
expect "UID 0 後門帳戶"                   "$out" "root 以外嘅 UID 0 帳戶：backdoor"

echo
echo "結果：PASS $PASS，FAIL $FAIL"
if [ "$FAIL" -gt 0 ]; then
    echo "---- 情況二完整輸出 ----"; echo "$out"
    exit 1
fi
