import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import { InviteService } from "../src/invite-service.js";
import { MemoryStore } from "../src/store.js";

describe("邀請碼登入規則", () => {
  it("新使用者使用有效邀請碼登入時會建立帳號並消耗一次", async () => {
    const store = new MemoryStore();
    await store.createInviteCode({ code: "JOIN-100", maxUses: 100 });
    const service = new InviteService(store);

    const result = await service.loginWithInvite({
      email: "Alice@Example.com",
      displayName: "Alice",
      inviteCode: "JOIN-100"
    });

    assert.equal(result.email, "alice@example.com");
    assert.equal(result.created, true);
    assert.equal((await store.getInviteCode("JOIN-100")).usedCount, 1);
  });

  it("新使用者不需要填名字並會分配固定顯示名稱", async () => {
    const store = new MemoryStore();
    await store.createInviteCode({ code: "JOIN-100", maxUses: 100 });
    const service = new InviteService(store);

    const result = await service.loginWithInvite({
      email: "name-free@example.com",
      inviteCode: "JOIN-100"
    });

    assert.equal(result.displayName, "Neko Maau");
  });

  it("邀請碼達到上限後會拒絕建立新使用者", async () => {
    const store = new MemoryStore();
    await store.createInviteCode({ code: "FULL", maxUses: 1 });
    const service = new InviteService(store);

    await service.loginWithInvite({
      email: "first@example.com",
      inviteCode: "FULL"
    });

    await assert.rejects(
      () =>
        service.loginWithInvite({
          email: "second@example.com",
          inviteCode: "FULL"
        }),
      /邀請碼使用次數已達上限/
    );
  });

  it("既有使用者登入不需要消耗新的邀請碼次數", async () => {
    const store = new MemoryStore();
    await store.createInviteCode({ code: "ONCE", maxUses: 1 });
    const service = new InviteService(store);

    await service.loginWithInvite({
      email: "member@example.com",
      inviteCode: "ONCE"
    });

    const result = await service.loginWithInvite({
      email: "MEMBER@example.com",
      inviteCode: "wrong-code"
    });

    assert.equal(result.email, "member@example.com");
    assert.equal(result.created, false);
    assert.equal((await store.getInviteCode("ONCE")).usedCount, 1);
  });
});
