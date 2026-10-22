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
apt-get install -y -qq php8.3-fpm php8.3-cli nodejs iproute2 procps >/dev/null 2>&1
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
expect_not() {  # expect_not <描述> <輸出> <唔應該出現嘅字串>
    if grep -qF -- "$3" <<<"$2"; then
        echo "  FAIL  $1（唔應該出現：$3）"; FAIL=$((FAIL + 1))
    else
        echo "  PASS  $1"; PASS=$((PASS + 1))
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
expect "偵測到 PHP 版本"                 "$out" "PHP 8.3."
expect "偵測到 Node.js 版本"             "$out" "Node.js 18."
expect "upload_progress 預設 On 會提示"   "$out" "PHP 8.3 FPM：On"
expect "冇 FPM 可疑子進程"               "$out" "冇發現 PHP-FPM 衍生可疑子進程"
expect "冇 webshell 特徵"                "$out" "冇發現常見 webshell 特徵"
expect "冇 UID 0 帳戶"                   "$out" "只有 root 係 UID 0"
expect "輸出結果行"                      "$out" "##RESULT##|"

# ---------- 情況二：佈置攻擊痕跡 ----------
# 等兩秒先改設定：時間戳只係精確到秒，要同 FPM 啟動時間分得開
sleep 2
sed -i 's/^;\?session.upload_progress.enabled.*/session.upload_progress.enabled = Off/' /etc/php/8.3/fpm/php.ini
# 假 webshell + 上傳目錄入面嘅 PHP 檔
echo '<?php eval(base64_decode($_POST["x"]));' > /home/forge/site/public/shell.php
echo '<?php' > /home/forge/site/storage/app/public/avatar.php
chown -R forge:forge /home/forge
# 假 access log（大部分來源係 Cloudflare IP，即係 nginx 冇還原真實 IP）
cat > /var/log/nginx/access.log <<'LOG'
172.70.1.1 - - [21/Oct/2026:09:00:00 +0000] "POST /login HTTP/1.1" 302 0 "-" "x"
172.70.1.1 - - [21/Oct/2026:09:00:01 +0000] "POST /login HTTP/1.1" 302 0 "-" "x"
104.22.1.1 - - [21/Oct/2026:09:00:02 +0000] "GET / HTTP/1.1" 200 10 "-" "x"
162.158.1.1 - - [21/Oct/2026:09:00:03 +0000] "GET / HTTP/1.1" 200 10 "-" "x"
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
# 模擬 AWS：cloud-init 預設用戶 ubuntu（Docker 映像本身已有 ubuntu 用戶並喺 sudo 群組）
mkdir -p /etc/cloud
printf 'system_info:\n  default_user:\n    name: ubuntu\n    groups: [adm, sudo]\n' > /etc/cloud/cloud.cfg
# 模擬已停止支援嘅 Ubuntu 20.04
sed -i 's/^VERSION_ID=.*/VERSION_ID="20.04"/' /etc/os-release
# nginx 網站設定：PHP、冇安裝嘅 PHP 版本、Node.js（直接 port 同 upstream）、靜態網站
mkdir -p /etc/nginx/sites-enabled /etc/nginx/conf.d
cat > /etc/nginx/sites-enabled/php.test <<'NG'
server { server_name php.test www.php.test; root /home/forge/php.test/public;
  location ~ \.php$ { fastcgi_pass unix:/var/run/php/php8.3-fpm.sock; } }
NG
cat > /etc/nginx/sites-enabled/old.test <<'NG'
server { server_name old.test; location ~ \.php$ { fastcgi_pass unix:/var/run/php/php7.4-fpm.sock; } }
NG
cat > /etc/nginx/sites-enabled/node.test <<'NG'
server { server_name node.test www.node.test; root /home/forge/node-app;
  location / { proxy_pass http://127.0.0.1:3000; }
  location ~ \.php$ { fastcgi_pass unix:/var/run/php/php8.3-fpm.sock; } }
NG
cat > /etc/nginx/sites-enabled/down.test <<'NG'
server { server_name down.test; location / { proxy_pass http://127.0.0.1:3999; } }
NG
cat > /etc/nginx/sites-enabled/default <<'NG'
server { listen 80 default_server; server_name 203.0.113.9; root /home/forge/default;
  location ~ \.php$ { fastcgi_pass unix:/var/run/php/php7.4-fpm.sock; } }
NG
cat > /etc/nginx/sites-enabled/up.test <<'NG'
server { server_name up.test; location / { proxy_pass http://nuxt_app; } }
NG
cat > /etc/nginx/conf.d/up.conf <<'NG'
upstream nuxt_app { server 127.0.0.1:3001; }
NG
cat > /etc/nginx/sites-enabled/static.test <<'NG'
server { server_name static.test; root /home/forge/static.test; }
NG
# 兩個監聽 port 嘅 Node.js 服務（用 root 執行，原因同下面 next-server 一樣）
mkdir -p /home/forge/node-app /home/forge/nuxt-app
(cd /home/forge/node-app && node -e 'require("http").createServer(()=>{}).listen(3000,"127.0.0.1")' >/dev/null 2>&1 &)
(cd /home/forge/nuxt-app && node -e 'require("http").createServer(()=>{}).listen(3001,"127.0.0.1")' >/dev/null 2>&1 &)
# 未修補嘅 Next.js 同 react-server-dom-webpack（假 package.json）
mkdir -p /home/forge/next-app/node_modules/next /home/forge/next-app/node_modules/react-server-dom-webpack
echo '{ "name": "next", "version": "16.4.0" }' > /home/forge/next-app/node_modules/next/package.json
echo '{ "name": "react-server-dom-webpack", "version": "19.2.8" }' > /home/forge/next-app/node_modules/react-server-dom-webpack/package.json
# 假 next-server 進程（Ubuntu 24.04 套件嘅 Node.js 18 已 EOL）
# 用 root 執行：Docker 預設冇 SYS_PTRACE，root 讀唔到其他用戶進程嘅 /proc/<pid>/exe
node -e 'process.title="next-server (v15.5.20)"; setInterval(()=>{},1000)' >/dev/null 2>&1 &

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
expect "運行中 EOL Node.js 為警告"         "$out" "有進程運行中）：已停止官方支援（EOL）"
expect "運行中 next-server 版本"          "$out" "[警告] Next.js 15.5.20（運行中嘅 next-server）"
expect "已部署 Next.js 16.4.0"            "$out" "[警告] Next.js 16.4.0（/home/forge/next-app）"
expect "react-server-dom-webpack 19.2.8" "$out" "[警告] react-server-dom-webpack 19.2.8"
expect "作業系統停止支援"                  "$out" "作業系統 ubuntu 20.04 已於 2025-05-29 停止標準支援"
expect "雲端預設用戶唔當可疑"              "$out" "雲端平台預設用戶（cloud-init 建立"
expect_not "雲端預設用戶唔觸發 sudo 警告"  "$out" "sudo 群組有非預期成員：ubuntu"
expect "網站對應：已修補 PHP"              "$out" "php.test → PHP 8.3"
expect "網站對應：www 別名唔重複"          "$out" "node.test → port 3000"
expect "網站對應：port 冇服務監聽"         "$out" "down.test → port 3999（冇服務監聽"
expect "網站對應：預設網站可以用 IP 連入"  "$out" "default（server_name：203.0.113.9）【可以用伺服器 IP 直接連入】"
expect_not "唔會讀 sync 用戶嘅 /bin"       "$out" "/bin/.ssh/authorized_keys"
expect "網站對應：冇安裝嘅 PHP 版本"       "$out" "old.test → PHP 7.4（呢部機冇安裝呢個版本嘅 FPM）"
expect "網站對應：Node.js 直接 port"       "$out" "node.test → port 3000 → Node.js 18."
expect "網站對應：Node.js 經 upstream"     "$out" "up.test → port 3001 → Node.js 18."
expect "網站對應：工作目錄"                "$out" "（/home/forge/node-app）：已停止支援"
expect "網站對應：靜態網站"                "$out" "冇 PHP／Node.js 處理嘅網站（靜態檔案或者轉址）：static.test"
expect "未對應網站嘅 Node 進程"            "$out" "冇經 nginx 對應任何網站"
expect "Cloudflare IP 比例"                "$out" "嘅請求來源係 Cloudflare IP"
expect "POST IP 標示 Cloudflare"           "$out" "172.70.1.1（Cloudflare）"
expect "改咗設定未 reload"                 "$out" "新設定未生效"

# ---------- 情況三：reload FPM 之後 ----------
kill -USR2 "$(cat /run/php/php8.3-fpm.pid)"
sleep 2
echo "== 情況三：reload FPM 之後 =="
out3=$(run_scan)
expect "reload 之後設定已生效"             "$out3" "新設定已生效"
expect_not "reload 之後冇未生效警告"       "$out3" "新設定未生效"

echo
echo "結果：PASS ${PASS}，FAIL ${FAIL}"
if [ "$FAIL" -gt 0 ]; then
    echo "---- 情況二完整輸出 ----"; echo "$out"
    exit 1
fi
