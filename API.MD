# SSO API 整合指南

本文件說明如何讓其他程式透過 API 呼叫本 SSO 系統的登入與註冊功能，無需經過網頁表單或人機驗證（Turnstile）。

## 系統背景

本 SSO 是一個 OIDC（OpenID Connect）提供者，部署於 Cloudflare Workers。標準流程是：

1. 客戶端將使用者導向 `/authorize`（顯示登入表單）
2. 使用者填寫表單、通過人機驗證後，系統產生授權碼（authorization code）並重導向回客戶端
3. 客戶端用授權碼向 `/token` 交換 JWT token

**API 端點跳過了第 1、2 步的網頁與人機驗證**，直接用 JSON 呼叫即可取得授權碼。

## 認證

所有 API 端點都需要 `ADMIN_TOKEN` 進行 Bearer 認證：

```
Authorization: Bearer <ADMIN_TOKEN>
```

`ADMIN_TOKEN` 的值在 SSO 伺服器的環境變數中設定。

## API 端點

### POST /api/login

登入已有帳號，取得 OIDC 授權碼。

**請求（JSON）：**

| 欄位 | 必填 | 說明 |
|------|------|------|
| `account` | 是 | 帳號名稱（不含 `@域名`），例如 `"alice"` |
| `client_id` | 否 | OIDC client ID，預設為伺服器設定的 `OIDC_CLIENT_ID` |
| `redirect_uri` | 否 | 回調 URL，預設為伺服器設定的第一個 `ALLOWED_REDIRECT_URIS` |
| `scope` | 否 | OIDC scope，預設 `"openid email"` |
| `state` | 否 | OIDC state 參數 |
| `nonce` | 否 | OIDC nonce 參數 |
| `code_challenge` | 否 | PKCE code challenge |
| `code_challenge_method` | 否 | PKCE 方法，僅支援 `"S256"` |

**回應（JSON）：**

```json
{
  "code": "abc123...",
  "redirect_uri": "https://example.com/callback?code=abc123...&state=...",
  "user": {
    "email": "alice@example.com",
    "displayName": "alice",
    "created": false
  }
}
```

- `code`：授權碼，可用於向 `/token` 交換 JWT token
- `redirect_uri`：拼好的完整回調 URL（含 code 和 state）
- `user`：使用者資訊

### POST /api/register

註冊新帳號（需要邀請碼），同時完成登入並取得授權碼。若帳號已存在則直接登入。

**請求（JSON）：**

| 欄位 | 必填 | 說明 |
|------|------|------|
| `account` | 是 | 帳號名稱（不含 `@域名`） |
| `invite_code` | 是 | 邀請碼 |
| `display_name` | 否 | 顯示名稱，預設為帳號名稱 |
| `client_id` | 否 | OIDC client ID |
| `redirect_uri` | 否 | 回調 URL |
| `scope` | 否 | OIDC scope |
| `state` | 否 | OIDC state |
| `nonce` | 否 | OIDC nonce |
| `code_challenge` | 否 | PKCE code challenge |
| `code_challenge_method` | 否 | PKCE 方法 |

**回應（JSON）：**

```json
{
  "code": "xyz789...",
  "redirect_uri": "https://example.com/callback?code=xyz789...",
  "user": {
    "email": "bob@example.com",
    "displayName": "bob",
    "created": true
  }
}
```

- `user.created`：`true` 表示新建帳號，`false` 表示帳號已存在並直接登入

## 錯誤回應

所有錯誤回傳 JSON，HTTP status 非 200：

```json
{ "error": "錯誤訊息" }
```

常見錯誤：
- `401` — 未提供或錯誤的 `ADMIN_TOKEN`
- `400` — 缺少必要欄位、帳號不存在、邀請碼無效、OIDC 參數不合法

## 完整使用流程

以下是讓你的程式整合本 SSO 的完整步驟：

```
1. 呼叫 /api/login 或 /api/register 取得授權碼（code）
2. 用授權碼呼叫 /token 交換 JWT token
3. 用 JWT token 存取受保護的資源
```

### 步驟 1：取得授權碼

```bash
curl -X POST https://sso.example.com/api/register \
  -H "Authorization: Bearer YOUR_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "account": "alice",
    "invite_code": "YOUR_INVITE_CODE",
    "redirect_uri": "https://your-app.com/callback",
    "client_id": "YOUR_CLIENT_ID"
  }'
```

### 步驟 2：用授權碼交換 token

```bash
curl -X POST https://sso.example.com/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "code=上一步拿到的 code" \
  -d "redirect_uri=https://your-app.com/callback" \
  -d "client_id=YOUR_CLIENT_ID" \
  -d "client_secret=YOUR_CLIENT_SECRET"
```

回應：

```json
{
  "access_token": "eyJ...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "id_token": "eyJ..."
}
```

### 步驟 3（可選）：查詢使用者資訊

```bash
curl https://sso.example.com/userinfo \
  -H "Authorization: Bearer <access_token>"
```

## 修改其他程式的整合範例

假設你要讓一個程式在啟動時自動透過本 SSO 取得 token，以下是 Node.js 範例：

```javascript
async function ssoLogin({ baseUrl, adminToken, account, inviteCode, clientId, clientSecret, redirectUri }) {
  // 步驟 1：註冊或登入
  const endpoint = inviteCode ? "/api/register" : "/api/login";
  const body = { account, client_id: clientId, redirect_uri: redirectUri };
  if (inviteCode) body.invite_code = inviteCode;

  const res = await fetch(`${baseUrl}${endpoint}`, {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${adminToken}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify(body)
  });

  if (!res.ok) throw new Error(`SSO 登入失敗: ${JSON.stringify(await res.json())}`);
  const { code } = await res.json();

  // 步驟 2：交換 token
  const params = new URLSearchParams({
    grant_type: "authorization_code",
    code,
    redirect_uri: redirectUri,
    client_id: clientId,
    client_secret: clientSecret
  });

  const tokenRes = await fetch(`${baseUrl}/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: params
  });

  if (!tokenRes.ok) throw new Error(`Token 交換失敗: ${JSON.stringify(await tokenRes.json())}`);
  return tokenRes.json(); // { access_token, id_token, expires_in, token_type }
}
```

## 注意事項

- 授權碼預設有效期為 5 分鐘（`AUTHORIZATION_CODE_TTL_SECONDS`），且只能使用一次
- token 預設有效期為 1 小時（`TOKEN_TTL_SECONDS`）
- `account` 欄位只能是英文字母、數字、點、底線、加號、連字號
- 所有帳號自動加上 `@ACCOUNT_DOMAIN` 後綴作為 email
- 若 `/api/register` 的帳號已存在，會直接登入而不報錯（`user.created` 為 `false`）
