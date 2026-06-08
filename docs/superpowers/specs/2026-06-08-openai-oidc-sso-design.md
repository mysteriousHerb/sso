# OpenAI OIDC SSO 設計

## 目標

建立一個可部署於 Cloudflare Workers 的 OIDC 身分提供者，用於對接 OpenAI 的 Custom OIDC SSO。使用者登入時輸入電子郵件與邀請碼；已建立的使用者可持續登入，新使用者必須使用有效邀請碼，且單一邀請碼預設最多只能建立 100 個帳號。

## 協議選型

本專案使用 OIDC，而非 SAML。OIDC 使用 JSON 與 JWT，適合 Cloudflare Workers 的 WebCrypto 與無狀態 HTTP 模型；SAML 依賴 XML 簽名與斷言處理，實作與驗證成本較高。

OpenAI 官方 SSO 說明指出，完成網域驗證後可選擇 Custom OIDC 連接，並需將 IdP 應用程式與 OpenAI 設定精靈互相配置。OpenAI 使用者模型至少需要電子郵件，名字與姓氏為建議欄位。

## 架構

Worker 提供 OIDC Provider 端點與一個簡單登入頁。D1 儲存使用者、邀請碼與一次性授權碼。JWT 使用 RS256 金鑰簽名，公開金鑰透過 JWKS 端點提供給 OpenAI 驗證。

系統只信任設定中的 `OIDC_CLIENT_ID`、`OIDC_CLIENT_SECRET` 與 `ALLOWED_REDIRECT_URIS`。所有新帳號建立都必須先通過邀請碼限制；既有帳號登入不再消耗邀請碼。

## 端點

- `GET /.well-known/openid-configuration`：回傳 OIDC discovery metadata。
- `GET /jwks.json`：回傳公開 JWK。
- `GET /authorize`：驗證 OIDC 請求並顯示登入表單。
- `POST /login`：處理電子郵件與邀請碼，建立授權碼並導回 OpenAI。
- `POST /token`：驗證授權碼與 client 認證，簽發 `id_token`。
- `GET /userinfo`：透過 Bearer token 回傳使用者資訊。
- `POST /admin/invite-codes`：以 `ADMIN_TOKEN` 保護，用於建立邀請碼。
- `GET /admin/invite-codes`：以 `ADMIN_TOKEN` 保護，用於查看邀請碼使用狀態。

## 資料模型

- `users`：`email`、`display_name`、`invite_code`、`created_at`、`last_login_at`。
- `invite_codes`：`code`、`max_uses`、`used_count`、`enabled`、`created_at`。
- `authorization_codes`：一次性 OIDC 授權碼、使用者、client、redirect URI、nonce、scope、過期時間與使用時間。

## 安全與限制

電子郵件一律轉為小寫並去除前後空白。授權碼短期有效且只能使用一次。邀請碼建立新使用者時以 D1 transaction 保證計數與使用者建立一致。登入頁與錯誤訊息使用繁體中文。專案不實作密碼、二階段驗證或自助邀請碼管理介面，避免超出本次需求。

## 測試策略

以 Node.js 內建測試框架覆蓋核心行為：邀請碼上限、既有使用者登入、OIDC discovery、JWKS、授權碼交換、client secret 驗證與錯誤回應。測試使用記憶體儲存介面，避免依賴 Cloudflare 運行環境。
