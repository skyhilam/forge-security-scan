# forge-security-scan

[![CI](https://github.com/skyhilam/forge-security-scan/actions/workflows/ci.yml/badge.svg)](https://github.com/skyhilam/forge-security-scan/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

一個 Bash 腳本，喺你自己部電腦透過 SSH 快速排查一部或多部 **Laravel Forge** 伺服器：

- `session.upload_progress.enabled` 係咪已經關閉
- 有冇被攻擊嘅跡象

全程**只讀**：唔會改設定、唔會重啟服務，亦唔會喺伺服器寫入任何檔案。

> English summary: a read-only, agentless Bash script that SSHes into one or more Laravel Forge
> servers and checks PHP versions, whether `session.upload_progress.enabled` is Off, and indicators
> of compromise (suspicious PHP-FPM child processes, `PHP_SESSION_UPLOAD_PROGRESS`/LFI requests in
> access logs, recently modified PHP files and webshell signatures, suspicious system users).
> Output is in Traditional Chinese (Cantonese).

## 點解要檢查 `session.upload_progress`？

`session.upload_progress.enabled` 預設係 **On**。只要攻擊者喺 multipart 上傳請求入面加一個
`PHP_SESSION_UPLOAD_PROGRESS` 欄位，PHP 就會將攻擊者控制嘅內容寫入伺服器上嘅 session 檔，**唔理個網站
有冇用 PHP session 都會發生**。如果配合檔案包含（LFI）或者反序列化漏洞，就可以變成遠端執行程式碼（RCE）。

Laravel 唔使用 PHP 原生 session，亦用唔著 upload progress，所以**關閉佢通常唔會有任何影響**。

## 快速開始

```bash
curl -fsSLO https://raw.githubusercontent.com/skyhilam/forge-security-scan/main/forge-security-scan.sh
chmod +x forge-security-scan.sh

# 想先睇清楚會喺伺服器執行啲乜（建議）
./forge-security-scan.sh -P | less

# 掃描一部伺服器（預設用戶 forge）
./forge-security-scan.sh 203.0.113.10
```

**需要：**

- **本機：** macOS 或 Linux，有 `bash`（macOS 內置嘅 bash 3.2 都得）同 `ssh`
- **伺服器：** Forge 預設嘅 Ubuntu。唔需要喺伺服器安裝任何嘢，腳本會經 SSH 傳過去執行

## 用法

```bash
# 多部伺服器，每部可以指定唔同用戶同 port
./forge-security-scan.sh web1.example.com root@web2.example.com:2222

# 從清單檔讀取，檢查最近 14 日，報告存去 ./reports
cp servers.example.txt servers.txt   # 編輯成你嘅伺服器
./forge-security-scan.sh -f servers.txt -d 14 -o ./reports -i ~/.ssh/id_ed25519
```

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

伺服器格式：`[用戶@]主機[:port]`

**結束碼：**

| 結束碼 | 意思 |
|---|---|
| `0` | 全部正常 |
| `1` | 有「注意」項目 |
| `2` | 有「警告」項目 |
| `3` | 有伺服器連線失敗 |

可以直接用喺 cron 或者 CI 做監察。

### 喺伺服器上直接執行

如果你已經 SSH 入咗伺服器，可以直接喺伺服器上面跑：

```bash
./forge-security-scan.sh -P | bash -s -- 7 20 1 1
#                                         │  │  │ └ 嘗試 sudo -n（1/0）
#                                         │  │  └── 顏色（1/0）
#                                         │  └───── 每項最多顯示行數
#                                         └──────── 檢查日數
```

## 檢查項目

| # | 項目 | 內容 |
|---|---|---|
| 1 | PHP 版本 | `/etc/php/*` 入面每個版本、FPM 有冇運行、標示已 EOL 嘅版本 |
| 2 | `session.upload_progress.enabled` | 會檢查：<br>• 每個 FPM 版本嘅 `php.ini`<br>• 每個 pool 嘅 `php_admin_value` 覆寫<br>• `.user.ini` 同 nginx `PHP_VALUE`<br>• 改完設定之後 FPM 有冇 reload |
| 3-1 | 可疑子進程 | 會檢查：<br>• bash／sh／curl／wget／nc／python／perl 等進程係咪由 `php-fpm` 開出嚟<br>• 由 `/tmp`、`/dev/shm` 執行嘅進程<br>• 執行檔已被刪除嘅進程<br>• 挖礦程式<br>• 疑似 reverse shell 嘅連線<br>• crontab |
| 3-2 | Access log | 會搵：<br>• `PHP_SESSION_UPLOAD_PROGRESS` 請求<br>• multipart 請求<br>• LFI／`sess_` 檔包含<br>• POST 到 `index.php` 以外嘅 PHP 檔<br>• POST 最多嘅 IP<br>• Laravel log 入面嘅相關記錄<br>• **session 檔入面有冇 `upload_progress_` 資料** |
| 3-3 | PHP 檔案 | 會檢查：<br>• 最近改動嘅 `.php`／`.phtml`／`.phar` 等（mtime + ctime），按位置分類<br>• webshell 特徵碼<br>• Laravel `public/` 入面有冇 `index.php` 以外嘅 PHP 檔<br>• `storage/app` 有冇 PHP 檔<br>• 暫存目錄 |
| 3-4 | 系統用戶 | 會檢查：<br>• root 以外嘅 UID 0 帳戶<br>• 非預期嘅可登入帳戶<br>• sudo 群組成員<br>• passwd／shadow／sudoers 最近有冇改動<br>• auth.log／journal 嘅 `useradd` 記錄<br>• `authorized_keys` 指紋<br>• 最近登入記錄 |

輸出示例（節錄）：

```
━━━ 2. session.upload_progress.enabled（建議設為 Off） ━━━
  [注意] PHP 8.3 FPM：On —— 受影響：www.conf（CLI = On）；建議喺 /etc/php/8.3/fpm/php.ini 設 session.upload_progress.enabled = Off 然後 reload FPM

━━━ 3-2. 攻擊跡象：Access log（multipart／PHP_SESSION_UPLOAD_PROGRESS／LFI） ━━━
  [警告] 發現 1 個包含 PHP_SESSION_UPLOAD_PROGRESS／upload_progress 嘅請求：
        5.6.7.8 - - [21/Oct/2026:10:00:01 +0000] "GET /?PHP_SESSION_UPLOAD_PROGRESS=1 HTTP/1.1" 200 12 "-" "x"

══════════════════════════════ 總結 ══════════════════════════════
Server                                    Alert   Warn   Status
forge@203.0.113.10                            1      1   警告
```

輸出分四級：

| 級別 | 意思 |
|---|---|
| `[警告]` | 強烈攻擊跡象，要即刻處理 |
| `[注意]` | 需要人手判斷 |
| `[資訊]` | 供參考 |
| `[略過]` | 權限不足，冇檢查到 |

## 安全承諾

- 遠端只會執行讀取指令，唔會寫檔、改設定或者重啟服務，亦唔會建立暫存檔。
- 腳本係單一檔案，冇任何外部依賴。用 `-P` 可以睇到完整嘅遠端腳本。
- SSH 用 `BatchMode=yes`，唔會停低等你輸入密碼。
- `sudo` 只會用 `sudo -n` 嚟讀取 root 擁有嘅 log，唔會要求輸入密碼。

## 限制

- **Forge 預設 `access_log off`。** 大部分網站嘅請求唔會寫入 access log，腳本會列出係邊啲網站。
- **POST 內容同 `Content-Type` 唔會出現喺預設 log 格式。** 所以 multipart 上傳只可以間接判斷。
- **`forge` 用戶預設冇免密碼 sudo。** root 擁有嘅 log、`/var/lib/php/sessions`、`/root/.ssh` 會顯示「略過」。想做完整檢查，可以用 `-u root`，或者暫時幫 `forge` 設定 sudo NOPASSWD。
- **進程檢查只係即時快照。** 一次性嘅攻擊指令可能已經結束咗，所以要配合 log 同檔案一齊判斷。
- **「注意」級嘅項目要人手判斷。** 例如以下情況都可能係正常嘅：
  - 最近部署過，好多 PHP 檔都會變成「最近改動」
  - WordPress 網站嘅 `wp-*.php`
  - Forge 網站隔離（isolation）建立嘅用戶
- **冇發現異常唔代表一定冇被入侵。** 呢個工具係用嚟快速排查，唔可以取代完整嘅事故調查。

## 發現問題之後點做？

1. **關閉 upload progress。** 喺 Forge 後台揀「PHP → Edit FPM Configuration」，或者直接改
   `/etc/php/<版本>/fpm/php.ini`：
   ```ini
   session.upload_progress.enabled = Off
   ```
   然後 reload PHP-FPM（Forge 後台「Restart PHP」，或者 `sudo service php8.3-fpm reload`）。
   再跑一次本腳本，確認顯示 `Off`。
2. **有「警告」嘅話，先保留證據，再清理。** 保留嘅嘢包括 log、可疑檔案、`ps` 輸出。
3. **假設 credential 已經外洩，全部輪換。** 包括：
   - `.env` 入面嘅 `APP_KEY`、資料庫密碼、API key
   - SSH key
4. **搵出入侵點。** 例如有 LFI 或者反序列化漏洞嘅程式碼、過時嘅套件。必要時重建伺服器。

## 開發

```bash
# 靜態檢查（包括遠端腳本）
shellcheck -S warning forge-security-scan.sh tests/smoke-test.sh
./forge-security-scan.sh -P | shellcheck -s bash -S warning -

# 煙霧測試：喺用完即棄嘅 Ubuntu container 佈置假攻擊痕跡，確認全部揾得到
docker run --rm -v "$PWD":/src:ro -w /src ubuntu:24.04 bash tests/smoke-test.sh
```

歡迎提交 Issue 同 Pull Request，例如新嘅偵測規則、減少誤報、支援其他環境。

## 免責聲明

本工具以「現狀」提供，只用作輔助排查，唔保證可以發現所有入侵。請只喺你有權管理嘅伺服器上使用。

## License

[MIT](LICENSE)
