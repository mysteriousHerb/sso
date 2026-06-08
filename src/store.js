export class MemoryStore {
  constructor(now = () => new Date()) {
    this.now = now;
    this.users = new Map();
    this.inviteCodes = new Map();
    this.authorizationCodes = new Map();
  }

  async createInviteCode({ code, maxUses = 100, enabled = true }) {
    const normalizedCode = normalizeInviteCode(code);
    const now = this.now().toISOString();
    const record = {
      code: normalizedCode,
      maxUses,
      usedCount: 0,
      enabled,
      createdAt: now
    };
    this.inviteCodes.set(normalizedCode, record);
    return { ...record };
  }

  async getInviteCode(code) {
    const record = this.inviteCodes.get(normalizeInviteCode(code));
    return record ? { ...record } : null;
  }

  async getUserByEmail(email) {
    const record = this.users.get(normalizeEmail(email));
    return record ? { ...record } : null;
  }

  async createUserWithInvite({ email, displayName, inviteCode }) {
    const normalizedEmail = normalizeEmail(email);
    const normalizedCode = normalizeInviteCode(inviteCode);
    const existingUser = this.users.get(normalizedEmail);
    if (existingUser) {
      return { user: { ...existingUser }, created: false };
    }

    const invite = this.inviteCodes.get(normalizedCode);
    if (!invite || !invite.enabled) {
      throw new Error("邀請碼無效或已停用");
    }
    if (invite.usedCount >= invite.maxUses) {
      throw new Error("邀請碼使用次數已達上限");
    }

    const now = this.now().toISOString();
    const user = {
      email: normalizedEmail,
      displayName: normalizeDisplayName(displayName, normalizedEmail),
      inviteCode: normalizedCode,
      createdAt: now,
      lastLoginAt: now
    };
    invite.usedCount += 1;
    this.users.set(normalizedEmail, user);
    return { user: { ...user }, created: true };
  }

  async updateUserLogin(email) {
    const normalizedEmail = normalizeEmail(email);
    const user = this.users.get(normalizedEmail);
    if (!user) {
      return null;
    }
    user.lastLoginAt = this.now().toISOString();
    return { ...user };
  }

  async saveAuthorizationCode(record) {
    this.authorizationCodes.set(record.code, { ...record });
    return { ...record };
  }

  async consumeAuthorizationCode(code) {
    const record = this.authorizationCodes.get(code);
    if (!record || record.usedAt) {
      return null;
    }
    const consumed = { ...record, usedAt: this.now().toISOString() };
    this.authorizationCodes.set(code, consumed);
    return consumed;
  }
}

export class D1Store {
  constructor(db) {
    this.db = db;
  }

  async createInviteCode({ code, maxUses = 100, enabled = true }) {
    const normalizedCode = normalizeInviteCode(code);
    const now = new Date().toISOString();
    await this.db
      .prepare(
        `INSERT INTO invite_codes (code, max_uses, used_count, enabled, created_at)
         VALUES (?, ?, 0, ?, ?)
         ON CONFLICT(code) DO UPDATE SET
           max_uses = excluded.max_uses,
           enabled = excluded.enabled`
      )
      .bind(normalizedCode, maxUses, enabled ? 1 : 0, now)
      .run();
    return this.getInviteCode(normalizedCode);
  }

  async getInviteCode(code) {
    const row = await this.db
      .prepare(
        `SELECT code, max_uses, used_count, enabled, created_at
         FROM invite_codes
         WHERE code = ?`
      )
      .bind(normalizeInviteCode(code))
      .first();
    return row ? inviteFromRow(row) : null;
  }

  async getUserByEmail(email) {
    const row = await this.db
      .prepare(
        `SELECT email, display_name, invite_code, created_at, last_login_at
         FROM users
         WHERE email = ?`
      )
      .bind(normalizeEmail(email))
      .first();
    return row ? userFromRow(row) : null;
  }

  async createUserWithInvite({ email, displayName, inviteCode }) {
    const normalizedEmail = normalizeEmail(email);
    const normalizedCode = normalizeInviteCode(inviteCode);
    const existingUser = await this.getUserByEmail(normalizedEmail);
    if (existingUser) {
      return { user: existingUser, created: false };
    }

    const now = new Date().toISOString();
    const inviteUpdate = await this.db
      .prepare(
        `UPDATE invite_codes
         SET used_count = used_count + 1
         WHERE code = ?
           AND enabled = 1
           AND used_count < max_uses`
      )
      .bind(normalizedCode)
      .run();
    if (inviteUpdate.meta.changes !== 1) {
      throw new Error("邀請碼無效或使用次數已達上限");
    }

    const userInsert = await this.db
      .prepare(
        `INSERT OR IGNORE INTO users
           (email, display_name, invite_code, created_at, last_login_at)
         VALUES (?, ?, ?, ?, ?)`
      )
      .bind(
        normalizedEmail,
        normalizeDisplayName(displayName, normalizedEmail),
        normalizedCode,
        now,
        now
      )
      .run();

    if (userInsert.meta.changes === 1) {
      return { user: await this.getUserByEmail(normalizedEmail), created: true };
    }

    const user = await this.getUserByEmail(normalizedEmail);
    if (user) {
      return { user, created: false };
    }
    throw new Error("建立使用者失敗");
  }

  async updateUserLogin(email) {
    const normalizedEmail = normalizeEmail(email);
    const now = new Date().toISOString();
    await this.db
      .prepare("UPDATE users SET last_login_at = ? WHERE email = ?")
      .bind(now, normalizedEmail)
      .run();
    return this.getUserByEmail(normalizedEmail);
  }

  async saveAuthorizationCode(record) {
    await this.db
      .prepare(
        `INSERT INTO authorization_codes
          (code, email, client_id, redirect_uri, scope, nonce, code_challenge,
           code_challenge_method, expires_at, used_at, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?)`
      )
      .bind(
        record.code,
        record.email,
        record.clientId,
        record.redirectUri,
        record.scope,
        record.nonce ?? null,
        record.codeChallenge ?? null,
        record.codeChallengeMethod ?? null,
        record.expiresAt,
        record.createdAt
      )
      .run();
    return { ...record };
  }

  async consumeAuthorizationCode(code) {
    const now = new Date().toISOString();
    const row = await this.db
      .prepare(
        `SELECT code, email, client_id, redirect_uri, scope, nonce,
                code_challenge, code_challenge_method, expires_at, used_at,
                created_at
         FROM authorization_codes
         WHERE code = ?`
      )
      .bind(code)
      .first();
    if (!row || row.used_at) {
      return null;
    }
    await this.db
      .prepare("UPDATE authorization_codes SET used_at = ? WHERE code = ? AND used_at IS NULL")
      .bind(now, code)
      .run();
    return authorizationCodeFromRow({ ...row, used_at: now });
  }
}

export function normalizeEmail(email) {
  const normalized = String(email ?? "").trim().toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalized)) {
    throw new Error("請輸入有效的電子郵件地址");
  }
  return normalized;
}

export function normalizeInviteCode(code) {
  const normalized = String(code ?? "").trim();
  if (!normalized) {
    throw new Error("請輸入邀請碼");
  }
  return normalized;
}

function normalizeDisplayName(displayName, email) {
  const normalized = String(displayName ?? "").trim();
  return normalized || email.split("@")[0];
}

function inviteFromRow(row) {
  return {
    code: row.code,
    maxUses: row.max_uses,
    usedCount: row.used_count,
    enabled: Boolean(row.enabled),
    createdAt: row.created_at
  };
}

function userFromRow(row) {
  return {
    email: row.email,
    displayName: row.display_name,
    inviteCode: row.invite_code,
    createdAt: row.created_at,
    lastLoginAt: row.last_login_at
  };
}

function authorizationCodeFromRow(row) {
  return {
    code: row.code,
    email: row.email,
    clientId: row.client_id,
    redirectUri: row.redirect_uri,
    scope: row.scope,
    nonce: row.nonce,
    codeChallenge: row.code_challenge,
    codeChallengeMethod: row.code_challenge_method,
    expiresAt: row.expires_at,
    usedAt: row.used_at,
    createdAt: row.created_at
  };
}
