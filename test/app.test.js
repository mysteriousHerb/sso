import { strict as assert } from "node:assert";
import { before, describe, it } from "node:test";

import { createApp } from "../src/app.js";
import { loadConfig } from "../src/config.js";
import { MemoryStore } from "../src/store.js";

let privateJwk;

before(async () => {
  const keyPair = await crypto.subtle.generateKey(
    {
      name: "RSASSA-PKCS1-v1_5",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256"
    },
    true,
    ["sign", "verify"]
  );
  privateJwk = await crypto.subtle.exportKey("jwk", keyPair.privateKey);
  privateJwk.kid = "app-test-key";
  privateJwk.alg = "RS256";
  privateJwk.use = "sig";
});

function createTestApp() {
  const store = new MemoryStore();
  const config = loadConfig({
    ISSUER: "https://sso.example.com",
    OIDC_CLIENT_ID: "openai-client",
    OIDC_CLIENT_SECRET: "secret",
    ALLOWED_REDIRECT_URIS: "https://auth.openai.com/oidc/callback",
    PRIVATE_JWK: JSON.stringify(privateJwk),
    ADMIN_TOKEN: "admin-token"
  });
  return { store, app: createApp({ store, config }) };
}

describe("Worker HTTP 端點", () => {
  it("/authorize 會顯示登入表單", async () => {
    const { app } = createTestApp();
    const response = await app.fetch(
      new Request(
        "https://sso.example.com/authorize?client_id=openai-client&redirect_uri=https%3A%2F%2Fauth.openai.com%2Foidc%2Fcallback&response_type=code&scope=openid%20email&state=abc"
      )
    );

    const html = await response.text();
    assert.equal(response.status, 200);
    assert.match(html, /OpenAI SSO 登入/);
    assert.match(html, /邀請碼/);
  });

  it("/login 成功後會導回 redirect_uri 並帶上授權碼", async () => {
    const { store, app } = createTestApp();
    await store.createInviteCode({ code: "JOIN", maxUses: 100 });
    const body = new URLSearchParams({
      email: "user@example.com",
      invite_code: "JOIN",
      client_id: "openai-client",
      redirect_uri: "https://auth.openai.com/oidc/callback",
      scope: "openid email",
      state: "state-1"
    });

    const response = await app.fetch(
      new Request("https://sso.example.com/login", {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body
      })
    );

    assert.equal(response.status, 302);
    const location = new URL(response.headers.get("location"));
    assert.equal(location.origin + location.pathname, "https://auth.openai.com/oidc/callback");
    assert.equal(location.searchParams.get("state"), "state-1");
    assert.ok(location.searchParams.get("code"));
  });

  it("/token 會接受表單格式並回傳 id_token", async () => {
    const { store, app } = createTestApp();
    await store.createInviteCode({ code: "JOIN", maxUses: 100 });
    const loginBody = new URLSearchParams({
      email: "user@example.com",
      invite_code: "JOIN",
      client_id: "openai-client",
      redirect_uri: "https://auth.openai.com/oidc/callback",
      scope: "openid email"
    });
    const loginResponse = await app.fetch(
      new Request("https://sso.example.com/login", {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: loginBody
      })
    );
    const code = new URL(loginResponse.headers.get("location")).searchParams.get("code");

    const tokenResponse = await app.fetch(
      new Request("https://sso.example.com/token", {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          grant_type: "authorization_code",
          code,
          client_id: "openai-client",
          client_secret: "secret",
          redirect_uri: "https://auth.openai.com/oidc/callback"
        })
      })
    );

    const token = await tokenResponse.json();
    assert.equal(tokenResponse.status, 200);
    assert.ok(token.id_token);
    assert.equal(token.token_type, "Bearer");
  });

  it("管理邀請碼端點需要 ADMIN_TOKEN", async () => {
    const { app } = createTestApp();
    const denied = await app.fetch(
      new Request("https://sso.example.com/admin/invite-codes", {
        method: "POST",
        body: JSON.stringify({ code: "JOIN", maxUses: 100 })
      })
    );

    assert.equal(denied.status, 401);

    const created = await app.fetch(
      new Request("https://sso.example.com/admin/invite-codes", {
        method: "POST",
        headers: {
          authorization: "Bearer admin-token",
          "content-type": "application/json"
        },
        body: JSON.stringify({ code: "JOIN", maxUses: 100 })
      })
    );

    assert.equal(created.status, 201);
    assert.equal((await created.json()).code, "JOIN");
  });
});
