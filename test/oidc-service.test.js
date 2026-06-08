import { strict as assert } from "node:assert";
import { before, describe, it } from "node:test";

import { loadConfig } from "../src/config.js";
import { createCodeVerifier, exportPublicJwk, signJwt, verifyJwt } from "../src/crypto.js";
import { InviteService } from "../src/invite-service.js";
import { OidcService } from "../src/oidc-service.js";
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
  privateJwk.kid = "test-key";
  privateJwk.alg = "RS256";
  privateJwk.use = "sig";
});

function createService() {
  const store = new MemoryStore();
  const config = loadConfig({
    ISSUER: "https://sso.example.com",
    OIDC_CLIENT_ID: "openai-client",
    OIDC_CLIENT_SECRET: "secret",
    ALLOWED_REDIRECT_URIS: "https://auth.openai.com/oidc/callback",
    PRIVATE_JWK: JSON.stringify(privateJwk),
    ADMIN_TOKEN: "admin"
  });
  return {
    store,
    config,
    service: new OidcService({ store, config, now: () => new Date("2026-06-08T00:00:00.000Z") })
  };
}

describe("OIDC 服務", () => {
  it("discovery metadata 會回傳必要端點", () => {
    const { service } = createService();

    const metadata = service.getDiscoveryMetadata();

    assert.equal(metadata.issuer, "https://sso.example.com");
    assert.equal(metadata.authorization_endpoint, "https://sso.example.com/authorize");
    assert.equal(metadata.token_endpoint, "https://sso.example.com/token");
    assert.equal(metadata.jwks_uri, "https://sso.example.com/jwks.json");
    assert.deepEqual(metadata.response_types_supported, ["code"]);
  });

  it("JWKS 只會公開公鑰欄位", async () => {
    const jwk = await exportPublicJwk(privateJwk);

    assert.equal(jwk.kid, "test-key");
    assert.equal(jwk.alg, "RS256");
    assert.equal(jwk.kty, "RSA");
    assert.ok(jwk.n);
    assert.ok(jwk.e);
    assert.equal(jwk.d, undefined);
    assert.equal(jwk.ext, undefined);
    assert.deepEqual(Object.keys(jwk).sort(), ["alg", "e", "kid", "kty", "n", "use"]);
  });

  it("未知 client 或 redirect URI 會被拒絕", () => {
    const { service } = createService();

    assert.throws(
      () =>
        service.validateAuthorizeRequest(
          new URLSearchParams({
            client_id: "wrong",
            redirect_uri: "https://auth.openai.com/oidc/callback",
            response_type: "code",
            scope: "openid email"
          })
        ),
      /不允許的 OIDC client/
    );

    assert.throws(
      () =>
        service.validateAuthorizeRequest(
          new URLSearchParams({
            client_id: "openai-client",
            redirect_uri: "https://evil.example.com/callback",
            response_type: "code",
            scope: "openid email"
          })
        ),
      /不允許的 redirect_uri/
    );
  });

  it("有效授權碼可以交換 id_token 並且只能使用一次", async () => {
    const { store, service, config } = createService();
    await store.createInviteCode({ code: "JOIN", maxUses: 100 });
    const inviteService = new InviteService(store);
    const user = await inviteService.loginWithInvite({
      email: "user@example.com",
      displayName: "Ada Lovelace",
      inviteCode: "JOIN"
    });

    const authCode = await service.createAuthorizationCode({
      user,
      clientId: "openai-client",
      redirectUri: "https://auth.openai.com/oidc/callback",
      scope: "openid email profile",
      nonce: "nonce-1"
    });

    const token = await service.exchangeCode({
      code: authCode.code,
      clientId: "openai-client",
      clientSecret: "secret",
      redirectUri: "https://auth.openai.com/oidc/callback"
    });

    assert.equal(token.token_type, "Bearer");
    assert.equal(token.expires_in, 3600);
    const claims = await verifyJwt(token.id_token, JSON.parse(config.privateJwk));
    assert.equal(claims.iss, "https://sso.example.com");
    assert.equal(claims.aud, "openai-client");
    assert.equal(claims.email, "user@example.com");
    assert.equal(claims.given_name, "Ada");
    assert.equal(claims.family_name, "Lovelace");
    assert.equal(claims.nonce, "nonce-1");

    await assert.rejects(
      () =>
        service.exchangeCode({
          code: authCode.code,
          clientId: "openai-client",
          clientSecret: "secret",
          redirectUri: "https://auth.openai.com/oidc/callback"
        }),
      /授權碼無效或已使用/
    );
  });

  it("錯誤 client secret 會被拒絕", async () => {
    const { store, service } = createService();
    await store.createInviteCode({ code: "JOIN", maxUses: 100 });
    const user = await new InviteService(store).loginWithInvite({
      email: "user@example.com",
      inviteCode: "JOIN"
    });
    const authCode = await service.createAuthorizationCode({
      user,
      clientId: "openai-client",
      redirectUri: "https://auth.openai.com/oidc/callback",
      scope: "openid email"
    });

    await assert.rejects(
      () =>
        service.exchangeCode({
          code: authCode.code,
          clientId: "openai-client",
          clientSecret: "bad-secret",
          redirectUri: "https://auth.openai.com/oidc/callback"
        }),
      /client_secret 驗證失敗/
    );
  });

  it("PKCE 驗證碼可以產生符合 OIDC 的挑戰值", async () => {
    const challenge = await createCodeVerifier("plain-verifier");

    assert.match(challenge, /^[A-Za-z0-9_-]+$/);
    assert.equal(challenge.includes("="), false);
  });

  it("JWT 簽名會包含指定標頭與宣告", async () => {
    const jwt = await signJwt({
      privateJwk,
      claims: { iss: "issuer", sub: "subject", aud: "audience" },
      now: () => new Date("2026-06-08T00:00:00.000Z")
    });

    const claims = await verifyJwt(jwt, privateJwk);
    assert.equal(claims.sub, "subject");
    assert.equal(claims.iat, 1780876800);
  });
});
