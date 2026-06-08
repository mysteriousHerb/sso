import { exportPublicJwk, timingSafeEqual, verifyJwt } from "./crypto.js";
import { InviteService } from "./invite-service.js";
import { OidcService } from "./oidc-service.js";

export function createApp({ store, config }) {
  const inviteService = new InviteService(store);
  const oidcService = new OidcService({ store, config });

  return {
    async fetch(request) {
      const url = new URL(request.url);
      try {
        if (request.method === "GET" && url.pathname === "/.well-known/openid-configuration") {
          return json(oidcService.getDiscoveryMetadata());
        }
        if (request.method === "GET" && url.pathname === "/jwks.json") {
          return json(
            { keys: [await exportPublicJwk(requirePrivateJwk(config))] },
            { headers: { "content-type": "application/jwk-set+json; charset=utf-8" } }
          );
        }
        if (request.method === "GET" && url.pathname === "/authorize") {
          return handleAuthorize(url, oidcService);
        }
        if (request.method === "POST" && url.pathname === "/login") {
          return handleLogin(request, inviteService, oidcService);
        }
        if (request.method === "POST" && url.pathname === "/token") {
          return handleToken(request, oidcService);
        }
        if (request.method === "GET" && url.pathname === "/userinfo") {
          return handleUserInfo(request, oidcService, config);
        }
        if (url.pathname === "/admin/invite-codes") {
          return handleInviteCodesAdmin(request, store, config);
        }
        return html("找不到頁面", { status: 404 });
      } catch (error) {
        return errorResponse(error);
      }
    }
  };
}

function handleAuthorize(url, oidcService) {
  const request = oidcService.validateAuthorizeRequest(url.searchParams);
  return html(renderLoginPage(request));
}

async function handleLogin(request, inviteService, oidcService) {
  const form = await request.formData();
  const authRequest = {
    clientId: String(form.get("client_id") ?? ""),
    redirectUri: String(form.get("redirect_uri") ?? ""),
    scope: String(form.get("scope") ?? "openid email"),
    state: String(form.get("state") ?? ""),
    nonce: String(form.get("nonce") ?? ""),
    codeChallenge: String(form.get("code_challenge") ?? ""),
    codeChallengeMethod: String(form.get("code_challenge_method") ?? "")
  };
  oidcService.validateAuthorizeRequest(
    new URLSearchParams({
      client_id: authRequest.clientId,
      redirect_uri: authRequest.redirectUri,
      response_type: "code",
      scope: authRequest.scope
    })
  );

  const user = await inviteService.loginWithInvite({
    email: String(form.get("email") ?? ""),
    inviteCode: String(form.get("invite_code") ?? "")
  });
  const code = await oidcService.createAuthorizationCode({
    user,
    clientId: authRequest.clientId,
    redirectUri: authRequest.redirectUri,
    scope: authRequest.scope,
    nonce: authRequest.nonce,
    codeChallenge: authRequest.codeChallenge,
    codeChallengeMethod: authRequest.codeChallengeMethod
  });
  const redirect = new URL(authRequest.redirectUri);
  redirect.searchParams.set("code", code.code);
  if (authRequest.state) {
    redirect.searchParams.set("state", authRequest.state);
  }
  return redirectResponse(redirect.toString());
}

async function handleToken(request, oidcService) {
  const form = await request.formData();
  const grantType = String(form.get("grant_type") ?? "");
  if (grantType !== "authorization_code") {
    return oauthError("unsupported_grant_type", "只支援 authorization_code", 400);
  }

  const credentials = parseClientCredentials(request, form);
  try {
    const token = await oidcService.exchangeCode({
      code: String(form.get("code") ?? ""),
      clientId: credentials.clientId,
      clientSecret: credentials.clientSecret,
      redirectUri: String(form.get("redirect_uri") ?? ""),
      codeVerifier: String(form.get("code_verifier") ?? "")
    });
    return json(token, {
      headers: { "cache-control": "no-store", pragma: "no-cache" }
    });
  } catch (error) {
    return oauthError("invalid_grant", error.message, 400);
  }
}

async function handleUserInfo(request, oidcService, config) {
  const authorization = request.headers.get("authorization") ?? "";
  const match = authorization.match(/^Bearer\s+(.+)$/i);
  if (!match) {
    return json({ error: "缺少 Bearer token" }, { status: 401 });
  }
  const claims = await verifyJwt(match[1], requirePrivateJwk(config));
  const info = await oidcService.getUserInfo(claims.email);
  return json(info);
}

async function handleInviteCodesAdmin(request, store, config) {
  if (!isAdmin(request, config)) {
    return json({ error: "未授權" }, { status: 401 });
  }
  if (request.method === "POST") {
    const body = await request.json();
    const inviteCode = await store.createInviteCode({
      code: body.code,
      maxUses: Number(body.maxUses ?? 100),
      enabled: body.enabled ?? true
    });
    return json(inviteCode, { status: 201 });
  }
  if (request.method === "GET") {
    return json({ message: "請直接查詢 D1，或用 POST 建立邀請碼。" });
  }
  return json({ error: "方法不允許" }, { status: 405 });
}

function parseClientCredentials(request, form) {
  const authorization = request.headers.get("authorization") ?? "";
  const basic = authorization.match(/^Basic\s+(.+)$/i);
  if (basic) {
    const decoded = atob(basic[1]);
    const [clientId, clientSecret] = decoded.split(":");
    return { clientId, clientSecret };
  }
  return {
    clientId: String(form.get("client_id") ?? ""),
    clientSecret: String(form.get("client_secret") ?? "")
  };
}

function isAdmin(request, config) {
  const authorization = request.headers.get("authorization") ?? "";
  const match = authorization.match(/^Bearer\s+(.+)$/i);
  return Boolean(match && timingSafeEqual(match[1], config.adminToken));
}

function requirePrivateJwk(config) {
  if (!config.privateJwk) {
    throw new Error("缺少必要設定：PRIVATE_JWK");
  }
  return parsePrivateJwk(config.privateJwk);
}

function parsePrivateJwk(value) {
  try {
    const jwk = JSON.parse(value);
    if (!jwk.kid) {
      throw new Error("PRIVATE_JWK 必須包含 kid");
    }
    return jwk;
  } catch (error) {
    if (error.message === "PRIVATE_JWK 必須包含 kid") {
      throw error;
    }
    throw new Error("PRIVATE_JWK 必須是有效的單行 JSON");
  }
}

function renderLoginPage(request) {
  const hiddenFields = {
    client_id: request.clientId,
    redirect_uri: request.redirectUri,
    scope: request.scope,
    state: request.state,
    nonce: request.nonce,
    code_challenge: request.codeChallenge,
    code_challenge_method: request.codeChallengeMethod
  };
  return `<!doctype html>
<html lang="zh-Hant">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>OpenAI SSO 登入</title>
  <style>
    :root { color-scheme: light; font-family: Arial, "Noto Sans TC", sans-serif; }
    body { margin: 0; min-height: 100vh; display: grid; place-items: center; background: #f7f7f5; color: #1f2328; }
    main { width: min(420px, calc(100vw - 32px)); background: #fff; border: 1px solid #d9d9d6; border-radius: 8px; padding: 28px; box-shadow: 0 18px 45px rgb(0 0 0 / 8%); }
    h1 { margin: 0 0 20px; font-size: 24px; line-height: 1.25; }
    label { display: grid; gap: 8px; margin: 14px 0; font-size: 14px; font-weight: 600; }
    input { box-sizing: border-box; width: 100%; border: 1px solid #c8c8c4; border-radius: 6px; padding: 11px 12px; font-size: 16px; }
    button { width: 100%; border: 0; border-radius: 6px; padding: 12px 14px; margin-top: 12px; background: #111; color: #fff; font-size: 16px; font-weight: 700; cursor: pointer; }
    p { margin: 0 0 16px; color: #5b5f66; line-height: 1.6; }
  </style>
</head>
<body>
  <main>
    <h1>OpenAI SSO 登入</h1>
    <p>請輸入電子郵件。新帳號需要有效邀請碼；已建立帳號可直接登入。</p>
    <form method="post" action="/login">
      ${Object.entries(hiddenFields)
        .map(([name, value]) => `<input type="hidden" name="${escapeHtml(name)}" value="${escapeHtml(value)}">`)
        .join("")}
      <label>電子郵件
        <input name="email" type="email" autocomplete="email" required>
      </label>
      <label>邀請碼
        <input name="invite_code" autocomplete="one-time-code">
      </label>
      <button type="submit">繼續</button>
    </form>
  </main>
</body>
</html>`;
}

function html(body, init = {}) {
  return new Response(body, {
    status: init.status ?? 200,
    headers: {
      "content-type": "text/html; charset=utf-8",
      ...init.headers
    }
  });
}

function json(body, init = {}) {
  return new Response(JSON.stringify(body), {
    status: init.status ?? 200,
    headers: {
      "content-type": "application/json; charset=utf-8",
      ...init.headers
    }
  });
}

function redirectResponse(location) {
  return new Response(null, {
    status: 302,
    headers: { location }
  });
}

function oauthError(error, description, status) {
  return json(
    {
      error,
      error_description: description
    },
    { status }
  );
}

function errorResponse(error) {
  return html(
    `<!doctype html><html lang="zh-Hant"><head><meta charset="utf-8"><title>登入失敗</title></head><body><h1>登入失敗</h1><p>${escapeHtml(error.message)}</p></body></html>`,
    { status: 400 }
  );
}

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}
