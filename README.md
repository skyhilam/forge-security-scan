# forge-security-scan

[![CI](https://github.com/skyhilam/forge-security-scan/actions/workflows/ci.yml/badge.svg)](https://github.com/skyhilam/forge-security-scan/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

經 SSH 快速排查 **Laravel Forge** 伺服器係咪受 **2026 年 10 月 PHP／Next.js／Node.js 重大漏洞**影響，逐個網站列出用緊邊個 PHP／Node.js 版本，同埋有冇被入侵嘅跡象。

全程**只讀**：唔會改設定、唔會重啟服務，亦唔會喺伺服器寫入任何檔案。

> English summary: a read-only, agentless Bash script that SSHes into one or more Laravel Forge
> servers and checks PHP/Node.js/Next.js versions against the October 2026 security releases
> (PHP CVE-2026-109618/109619 incl. Ubuntu backports, Next.js/React Server Components, Node.js),
> maps every nginx site to the PHP-FPM version or Node.js process that serves it, and looks for
> indicators of compromise. Output is in Traditional Chinese (Cantonese).

## ⚠ 2026 年 10 月重大漏洞

| 項目 | 漏洞 | 已修補版本 | 公布日期 |
|---|---|---|---|
| **PHP** | CVE-2026-109618、CVE-2026-109619：未經驗證遠端執行程式碼（Critical，CVSS 9.2） | **8.2.35／8.3.36／8.4.27／8.5.12** | 2026-10-21 |
| **Next.js** | `use cache` RCE、Image Optimization SVG RCE（CVE-2026-96889）、Server Actions DoS | **15.5.28／16.4.1** | 2026-10-14 |
| **React Server Components** | `react-server-dom-*` 未經驗證 RCE | **19.0.9／19.1.10／19.2.9／19.3.1** | 2026-10-14 |
| **Node.js** | Brotli 解壓 RCE（CVE-2026-111497）、TLS 主機名稱繞過等，共 10 個 | **22.23.4／24.22.1／26.12.1** | 2026-10-21 |

**重點：**

- PHP 官方嘅說法係：**「There are no complete mitigations, updating is the only safe choice.」**
  - `session.upload_progress.enabled = Off` 只係**部分緩解**，只可以堵住已知嘅 session upload progress 路徑，唔可以取代升級。
- 已 EOL 嘅版本冇修補，必須升級去有支援嘅分支：
  - PHP 8.1 或以下
  - Next.js 14 或以下
  - Node.js 22 以前，同埋 23、25
- Ubuntu／Debian 官方套件會 **backport** 修補，但係唔改版本號。例如 Ubuntu 24.04 嘅 `8.3.6-0ubuntu0.24.04.13` 已經修補咗。所以單睇版本號可能會誤判，`forge-security-scan.sh` 會讀套件 changelog 嚟確認。

**來源：**

- [PHP 公告](https://www.php.net/)：[GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)、[GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)
- [Next.js 安全公告](https://github.com/vercel/next.js/security/advisories)
- [Node.js 2026-10-21 Security Releases](https://nodejs.org/en/blog/vulnerability/october-2026-security-releases)

## 點解唔係輸入網址就檢查到？

由外部只可以睇到網站前端回應嘅資料。PHP 好多時喺後面做 API，版本亦通常收埋，同一部伺服器上其他網站更加睇唔到。我哋喺一部真實嘅 Forge 伺服器測試過：伺服器上運行緊 4 個未修補嘅 PHP 版本，但由外部檢查 12 個網站，**一個都偵測唔到 PHP**。所以要知道伺服器安唔安全，一定要入伺服器檢查。

## 用法

喺你自己部電腦經 SSH 掃描一部或多部 **Laravel Forge** 伺服器。唔使喺伺服器安裝任何嘢，腳本會經 SSH 傳過去執行。

```bash
curl -fsSLO https://raw.githubusercontent.com/skyhilam/forge-security-scan/main/forge-security-scan.sh
chmod +x forge-security-scan.sh

# 想先睇清楚會喺伺服器執行啲乜（建議）
./forge-security-scan.sh -P | less

# 掃描（預設用戶 forge）
./forge-security-scan.sh 203.0.113.10
./forge-security-scan.sh web1.example.com root@web2.example.com:2222

# 從清單檔讀取，檢查最近 14 日，報告存去 ./reports
cp servers.example.txt servers.txt   # 編輯成你嘅伺服器
./forge-security-scan.sh -f servers.txt -d 14 -o ./reports -i ~/.ssh/id_ed25519
```

**需要：**

- **本機：** macOS 或 Linux，有 `bash`（macOS 內置嘅 bash 3.2 都得）同 `ssh`
- **伺服器：** Forge 預設嘅 Ubuntu

**選項：**

| 選項 | 說明 | 預設 |
|---|---|---|
| `-f FILE` | 伺服器清單檔（每行一部，`#` 開頭係註解） | |
| `-u USER` | SSH 用戶 | `forge` |
| `-p PORT` | SSH port | 跟 `~/.ssh/config`，否則 22 |
| `-i KEY` | SSH 私鑰 | |
| `-d DAYS` | 檢查最近幾多日 | `7` |
| `-n LINES` | 每個項目最多顯示幾多行明細 | `20` |
| `-o DIR` | 將每部伺服器嘅純文字報告存去呢個目錄 | |
| `-S` | 唔好嘗試用 `sudo -n` | |
| `-C` | 唔輸出顏色 | |
| `-P` | 只印出會喺遠端執行嘅腳本，唔會連線 | |
| `-V` / `-h` | 版本／說明 | |

**結束碼：**

| 結束碼 | 意思 |
|---|---|
| `0` | 全部正常 |
| `1` | 有「注意」項目 |
| `2` | 有「警告」項目 |
| `3` | 有伺服器連線失敗 |

### 喺伺服器上直接執行

如果你已經 SSH 入咗伺服器，可以直接喺伺服器上面跑：

```bash
./forge-security-scan.sh -P | bash -s -- 7 20 1 1
#                                         │  │  │ └ 嘗試 sudo -n（1/0）
#                                         │  │  └── 顏色（1/0）
#                                         │  └───── 每項最多顯示行數
#                                         └──────── 檢查日數
```

### 檢查項目

| # | 項目 | 內容 |
|---|---|---|
| 1-1 | PHP 版本 | 每個已安裝版本對照 CVE-2026-109618／109619 嘅修補版本。會讀 Ubuntu／Debian 套件 changelog 判斷有冇 backport，標示 EOL 版本，未修補時列出升級指令同官方臨時措施 |
| 0 | 伺服器資訊 | 作業系統係咪已停止標準支援（例如 Ubuntu 20.04：apt 已經攞唔到 PHP 修補）、雲端平台同 cloud-init 預設用戶 |
| 1-2 | Node.js／Next.js | 會檢查：<br>• 已安裝嘅 Node.js（PATH、nvm、volta、fnm）同運行中嘅 node 進程<br>• 運行中 `next-server` 嘅版本<br>• 已部署專案入面 `node_modules` 嘅 `next` 同 `react-server-dom-*` |
| 1-3 | **網站對應** | 讀 nginx 設定，逐個網站列出由邊個 PHP-FPM 版本或者邊個 Node.js 進程處理（`proxy_pass` port → 進程 → 版本同工作目錄），直接睇到邊啲網站受影響。亦會標示：<br>• 可以用伺服器 IP 直接連入（繞過 Cloudflare）嘅預設網站<br>• nginx 有 PHP location 但網站目錄冇 PHP 檔（可以刪走，減少暴露）<br>• proxy port 冇服務監聽（已停用嘅網站） |
| 2 | `session.upload_progress.enabled` | 會檢查：<br>• 每個 FPM 版本嘅 `php.ini`<br>• 每個 pool 嘅覆寫<br>• `.user.ini` 同 nginx `PHP_VALUE`<br>• 改完設定之後 FPM 有冇 reload（由 pid 檔判斷，唔使 sudo） |
| 3-1 | 可疑子進程 | 會檢查：<br>• bash、curl、wget、nc、python 等進程係咪由 `php-fpm` 開出嚟<br>• 由 `/tmp` 執行嘅進程<br>• 執行檔已被刪除嘅進程<br>• 挖礦程式<br>• 疑似 reverse shell 嘅連線<br>• crontab |
| 3-2 | Access log | 會搵：<br>• `PHP_SESSION_UPLOAD_PROGRESS` 請求<br>• multipart 請求<br>• LFI<br>• POST 到 `index.php` 以外嘅 PHP 檔<br>• session 檔入面嘅 `upload_progress_` 資料<br>• 來源 IP 係咪大部分係 Cloudflare（即係 nginx 未還原真實訪客 IP） |
| 3-3 | PHP 檔案 | 會檢查：<br>• 最近改動嘅 PHP 檔<br>• webshell 特徵碼<br>• Laravel `public/` 入面有冇 `index.php` 以外嘅 PHP 檔<br>• `storage/app` 有冇 PHP 檔<br>• 暫存目錄 |
| 3-4 | 系統用戶 | 會檢查：<br>• root 以外嘅 UID 0 帳戶<br>• 非預期嘅可登入帳戶<br>• sudo 群組成員<br>• 帳戶檔有冇改動<br>• `useradd` 記錄<br>• `authorized_keys`<br>• 最近登入記錄 |

**輸出分級：**

| 級別 | 意思 |
|---|---|
| `[警告]` | 要即刻處理 |
| `[注意]` | 需要人手判斷 |
| `[資訊]` | 供參考 |
| `[略過]` | 權限不足，冇檢查到 |

**限制：**

- **Forge 預設 `access_log off`。** 大部分網站嘅請求唔會寫入 access log。
- **POST 內容唔會出現喺預設 log 格式。** 所以 multipart 上傳只可以間接判斷。
- **`forge` 用戶預設冇免密碼 sudo。** root 擁有嘅 log、`/var/lib/php/sessions`、其他用戶嘅進程會顯示「略過」。想做完整檢查，可以用 `-u root`。
- **進程檢查只係即時快照。** 一次性嘅攻擊指令可能已經結束咗。
- **冇發現異常唔代表一定冇被入侵。** 呢個工具係用嚟快速排查，唔可以取代完整嘅事故調查。

## 發現問題之後點做？

### 1. PHP：升級係唯一完整修補

Forge 用 ondrej PPA，可以直接升級：

```bash
sudo apt-get update && sudo apt-get install --only-upgrade 'php8.3-*'   # 換成你嘅版本
```

升級之後喺 Forge 後台「Restart PHP」，再跑一次 `forge-security-scan.sh` 確認。

**未能即時升級**，可以先用官方嘅臨時措施（**唔完整**，只可以爭取時間），然後重啟所有 worker：

- `session.upload_progress.enabled = 0`
- `memory_limit = -1`
- PHP 8.5：再加 `fatal_error_backtraces = 0`

**升級之後**，官方亦建議如果用唔著 upload progress，可以保持關閉。Laravel 本身用唔著呢個功能。

### 2. Next.js／React

升級到 `next@15.5.28` 或 `next@16.4.1` 以上，重新 build 同部署：

```bash
npm install next@latest
```

如果另外直接安裝咗 `react-server-dom-*`，一樣要升級。

### 3. Node.js

升級到 22.23.4／24.22.1／26.12.1 或以上，再重啟所有 Node 服務。EOL 版本（22 以前、23、25）要轉去有支援嘅版本。

### 4. 有入侵跡象（`[警告]`）

1. 先保留證據：log、可疑檔案、`ps` 輸出。
2. 假設所有 credential 已經外洩，全部輪換：
   - `.env` 入面嘅 `APP_KEY`、資料庫密碼、API key
   - SSH key
3. 搵出入侵點，必要時重建伺服器。

## 開發

```bash
# 靜態檢查（包括遠端腳本）
shellcheck -S warning forge-security-scan.sh tests/*.sh
./forge-security-scan.sh -P | shellcheck -s bash -S warning -

# 伺服器腳本煙霧測試：喺用完即棄嘅 Ubuntu container 佈置假攻擊痕跡同未修補版本
docker run --rm -v "$PWD":/src:ro -w /src ubuntu:24.04 bash tests/smoke-test.sh
```

有新安全公告時，只需要更新腳本入面嘅 `PHP_FIXED`、`NODE_FIXED`、`NEXT_FIXED`、`RSC_FIXED` 版本清單。歡迎提交 Issue 同 Pull Request。

## 免責聲明

本工具以「現狀」提供，只用作輔助排查，唔保證可以發現所有漏洞或入侵。請只喺你有權管理嘅網站同伺服器上使用。

## License

[MIT](LICENSE)
