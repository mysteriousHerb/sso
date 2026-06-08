# OpenAI OIDC SSO Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 建立可部署於 Cloudflare Workers 的 OpenAI Custom OIDC SSO Provider，支援邀請碼建立上限與既有使用者持續登入。

**Architecture:** Worker 負責 OIDC HTTP 端點、登入表單與 JWT 簽發；D1 儲存使用者、邀請碼與一次性授權碼；核心邏輯抽成可在 Node.js 測試中直接呼叫的純 JavaScript 模組。

**Tech Stack:** Cloudflare Workers ES module、D1、WebCrypto、Node.js 內建 `node:test`。

---

## 檔案結構

- `src/app.js`：Worker 路由、HTML 表單、OIDC 端點與回應。
- `src/config.js`：環境變數解析與設定驗證。
- `src/crypto.js`：RS256 JWK 匯入、JWT 簽名、雜湊與安全隨機值。
- `src/store.js`：D1 儲存介面與記憶體測試儲存介面。
- `src/invite-service.js`：使用者登入、邀請碼檢查與建立使用者。
- `src/oidc-service.js`：授權請求驗證、授權碼建立、token 簽發與 userinfo。
- `src/index.js`：Cloudflare Workers 入口。
- `schema.sql`：D1 資料表。
- `wrangler.toml`：Cloudflare Workers 設定範本。
- `.env.example`：部署所需變數範本。
- `test/*.test.js`：核心流程測試。
- `README.md`：繁體中文部署與 OpenAI 設定說明。
- `package.json`：測試與語法檢查指令。

## 任務

### Task 1: 專案骨架與設定

- [ ] 建立 `package.json`、`wrangler.toml`、`.env.example`。
- [ ] 建立 `src/index.js` 與基本模組檔。
- [ ] 建立 `schema.sql`。

### Task 2: 邀請碼與使用者登入

- [ ] 先寫測試：新使用者可用邀請碼登入並消耗一次。
- [ ] 先寫測試：邀請碼達上限後拒絕新使用者。
- [ ] 先寫測試：既有使用者可登入且不再消耗邀請碼。
- [ ] 實作 `MemoryStore`、`D1Store` 與 `InviteService`。

### Task 3: OIDC discovery、JWKS 與授權請求

- [ ] 先寫測試：discovery metadata 包含 OpenAI 需要的端點。
- [ ] 先寫測試：JWKS 回傳公開金鑰。
- [ ] 先寫測試：不允許未知 client 或 redirect URI。
- [ ] 實作 `OidcService` 的設定驗證與 metadata。

### Task 4: 授權碼與 token

- [ ] 先寫測試：有效授權碼可換取 RS256 `id_token`。
- [ ] 先寫測試：授權碼只能使用一次。
- [ ] 先寫測試：錯誤 client secret 被拒絕。
- [ ] 實作授權碼建立、消耗與 JWT 簽名。

### Task 5: Worker HTTP 端點

- [ ] 先寫測試：`/authorize` 顯示登入頁。
- [ ] 先寫測試：`/login` 成功後導回 OpenAI `redirect_uri`。
- [ ] 先寫測試：管理端點需要 `ADMIN_TOKEN`。
- [ ] 實作 Workers 路由與繁體中文錯誤頁。

### Task 6: 文件與驗證

- [ ] 補齊 `README.md` 的部署、D1 初始化、金鑰產生與 OpenAI Custom OIDC 設定。
- [ ] 執行 `node --test`。
- [ ] 執行 `node --check src/index.js`。
- [ ] 若可用，執行 `git diff --stat` 檢查變更範圍。
