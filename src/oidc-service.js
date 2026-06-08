import { randomUrlSafe, sha256Base64Url, signJwt, timingSafeEqual } from "./crypto.js";

export class OidcService {
  constructor({ store, config, now = () => new Date() }) {
    this.store = store;
    this.config = config;
    this.now = now;
  }

  getDiscoveryMetadata() {
    return {
      issuer: this.config.issuer,
      authorization_endpoint: `${this.config.issuer}/authorize`,
      token_endpoint: `${this.config.issuer}/token`,
      userinfo_endpoint: `${this.config.issuer}/userinfo`,
      jwks_uri: `${this.config.issuer}/jwks.json`,
      response_types_supported: ["code"],
      subject_types_supported: ["public"],
      id_token_signing_alg_values_supported: ["RS256"],
      scopes_supported: ["openid", "email", "profile"],
      token_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post"],
      claims_supported: [
        "sub",
        "iss",
        "aud",
        "exp",
        "iat",
        "email",
        "email_verified",
        "name",
        "given_name",
        "family_name"
      ]
    };
  }

  validateAuthorizeRequest(params) {
    const clientId = params.get("client_id");
    const redirectUri = params.get("redirect_uri");
    const responseType = params.get("response_type");
    const scope = params.get("scope") ?? "";
    if (clientId !== this.config.clientId) {
      throw new Error("不允許的 OIDC client");
    }
    if (!this.config.redirectUris.includes(redirectUri)) {
      throw new Error("不允許的 redirect_uri");
    }
    if (responseType !== "code") {
      throw new Error("只支援 authorization code flow");
    }
    if (!scope.split(/\s+/).includes("openid")) {
      throw new Error("scope 必須包含 openid");
    }
    return {
      clientId,
      redirectUri,
      responseType,
      scope,
      state: params.get("state") ?? "",
      nonce: params.get("nonce") ?? "",
      codeChallenge: params.get("code_challenge") ?? "",
      codeChallengeMethod: params.get("code_challenge_method") ?? ""
    };
  }

  async createAuthorizationCode({ user, clientId, redirectUri, scope, nonce, codeChallenge, codeChallengeMethod }) {
    const now = this.now();
    const code = randomUrlSafe(32);
    const record = {
      code,
      email: user.email,
      clientId,
      redirectUri,
      scope,
      nonce,
      codeChallenge,
      codeChallengeMethod,
      expiresAt: new Date(now.getTime() + this.config.authorizationCodeTtlSeconds * 1000).toISOString(),
      usedAt: null,
      createdAt: now.toISOString()
    };
    await this.store.saveAuthorizationCode(record);
    return record;
  }

  async exchangeCode({ code, clientId, clientSecret, redirectUri, codeVerifier }) {
    if (clientId !== this.config.clientId) {
      throw new Error("不允許的 OIDC client");
    }
    if (!timingSafeEqual(clientSecret, this.config.clientSecret)) {
      throw new Error("client_secret 驗證失敗");
    }

    const record = await this.store.consumeAuthorizationCode(code);
    if (!record) {
      throw new Error("授權碼無效或已使用");
    }
    if (new Date(record.expiresAt).getTime() < this.now().getTime()) {
      throw new Error("授權碼已過期");
    }
    if (record.clientId !== clientId || record.redirectUri !== redirectUri) {
      throw new Error("授權碼請求不一致");
    }
    if (record.codeChallenge) {
      await verifyPkce(record, codeVerifier);
    }

    const user = await this.store.getUserByEmail(record.email);
    if (!user) {
      throw new Error("找不到授權碼對應的使用者");
    }
    const idToken = await this.createIdToken({ user, nonce: record.nonce });
    return {
      access_token: await this.createAccessToken(user),
      token_type: "Bearer",
      expires_in: this.config.tokenTtlSeconds,
      id_token: idToken
    };
  }

  async createIdToken({ user, nonce }) {
    const privateJwk = this.requirePrivateJwk();
    const name = splitDisplayName(user.displayName, user.email);
    const claims = {
      iss: this.config.issuer,
      sub: user.email,
      aud: this.config.clientId,
      email: user.email,
      email_verified: true,
      name: user.displayName,
      given_name: name.givenName,
      family_name: name.familyName
    };
    if (nonce) {
      claims.nonce = nonce;
    }
    return signJwt({
      privateJwk,
      claims,
      now: this.now,
      ttlSeconds: this.config.tokenTtlSeconds
    });
  }

  async createAccessToken(user) {
    const privateJwk = this.requirePrivateJwk();
    return signJwt({
      privateJwk,
      claims: {
        iss: this.config.issuer,
        sub: user.email,
        aud: this.config.clientId,
        email: user.email
      },
      now: this.now,
      ttlSeconds: this.config.tokenTtlSeconds
    });
  }

  async getUserInfo(email) {
    const user = await this.store.getUserByEmail(email);
    if (!user) {
      throw new Error("找不到使用者");
    }
    const name = splitDisplayName(user.displayName, user.email);
    return {
      sub: user.email,
      email: user.email,
      email_verified: true,
      name: user.displayName,
      given_name: name.givenName,
      family_name: name.familyName
    };
  }

  requirePrivateJwk() {
    if (!this.config.privateJwk) {
      throw new Error("缺少必要設定：PRIVATE_JWK");
    }
    return parsePrivateJwk(this.config.privateJwk);
  }
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

function splitDisplayName(displayName, email) {
  const fallback = email.split("@")[0];
  const parts = String(displayName || fallback)
    .trim()
    .split(/\s+/)
    .filter(Boolean);
  const givenName = parts[0] || fallback;
  const familyName = parts.length > 1 ? parts.slice(1).join(" ") : givenName;
  return { givenName, familyName };
}

async function verifyPkce(record, verifier) {
  if (!verifier) {
    throw new Error("缺少 PKCE code_verifier");
  }
  if (record.codeChallengeMethod && record.codeChallengeMethod !== "S256") {
    throw new Error("只支援 S256 PKCE");
  }
  const expected = await sha256Base64Url(verifier);
  if (!timingSafeEqual(expected, record.codeChallenge)) {
    throw new Error("PKCE 驗證失敗");
  }
}
