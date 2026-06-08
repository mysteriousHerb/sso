# Cloudflare Workers OpenAI OIDC SSO

這是一個部署於 Cloudflare Workers 的 Custom OIDC SSO Provider，用於對接 OpenAI SSO。使用者登入時輸入電子郵件與邀請碼；邀請碼預設最多建立 100 個新帳號。已建立帳號之後仍可登入，不會再消耗邀請碼。

## 功能

- OIDC discovery：`/.well-known/openid-configuration`
- JWKS：`/jwks.json`
- 授權端點：`/authorize`
- 登入端點：`/login`
- Token 端點：`/token`
- UserInfo 端點：`/userinfo`
- 邀請碼管理：`/admin/invite-codes`

## OpenAI 設定

在 OpenAI SSO 設定頁選擇 **Custom OIDC**。建議填入：

- Issuer：`https://你的網域`
- Authorization endpoint：`https://你的網域/authorize`
- Token endpoint：`https://你的網域/token`
- JWKS URI：`https://你的網域/jwks.json`
- UserInfo endpoint：`https://你的網域/userinfo`
- Client ID：與 `OIDC_CLIENT_ID` 相同
- Client Secret：與 `OIDC_CLIENT_SECRET` 相同

OpenAI 的實際 callback URL 以 OpenAI 後台顯示為準，並放入 `ALLOWED_REDIRECT_URIS`。若有多個 redirect URI，使用逗號分隔。

## 建立 D1

```powershell
pnpm wrangler d1 create openai_oidc_sso
pnpm wrangler d1 execute openai_oidc_sso --file schema.sql
```

將 `wrangler d1 create` 回傳的 `database_id` 填入 `wrangler.toml`。

## 產生 RS256 私鑰 JWK

```powershell
node -e "crypto.subtle.generateKey({name:'RSASSA-PKCS1-v1_5',modulusLength:2048,publicExponent:new Uint8Array([1,0,1]),hash:'SHA-256'},true,['sign','verify']).then(k=>crypto.subtle.exportKey('jwk',k.privateKey)).then(j=>{j.kid='openai-sso-2026-06-08';j.alg='RS256';j.use='sig';console.log(JSON.stringify(j))})"
```

把輸出設定為 Workers secret：

```powershell
pnpm wrangler secret put PRIVATE_JWK
pnpm wrangler secret put OIDC_CLIENT_SECRET
pnpm wrangler secret put ADMIN_TOKEN
```

非機密設定已放在 `wrangler.toml` 的 `[vars]` 中，使用 GitHub 或 Cloudflare 網頁版部署時會一起生效：

- `ISSUER`
- `OIDC_CLIENT_ID`
- `ALLOWED_REDIRECT_URIS`
- `AUTHORIZATION_CODE_TTL_SECONDS`
- `TOKEN_TTL_SECONDS`

`ADMIN_TOKEN` 只在需要使用 `/admin/invite-codes` API 時才需要設定，建議作為 Workers secret 保存。若不設定，仍可直接在 D1 Console 用 SQL 建立邀請碼。

## 建立邀請碼

```powershell
curl -X POST https://你的網域/admin/invite-codes ^
  -H "Authorization: Bearer 你的_ADMIN_TOKEN" ^
  -H "Content-Type: application/json" ^
  -d "{\"code\":\"JOIN-2026\",\"maxUses\":100}"
```

回傳範例：

```json
{
  "code": "JOIN-2026",
  "maxUses": 100,
  "usedCount": 0,
  "enabled": true,
  "createdAt": "2026-06-08T00:00:00.000Z"
}
```

## 本地驗證

```powershell
pnpm install
pnpm test
pnpm check
```

## 部署

```powershell
pnpm wrangler deploy
```

部署後先開啟：

- `https://你的網域/.well-known/openid-configuration`
- `https://你的網域/jwks.json`

確認兩個端點正常後，再到 OpenAI 後台啟用 Custom OIDC。
