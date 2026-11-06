import { afterEach, describe, expect, it, vi } from "vitest";
import type { PluginConnectPolicyInput } from "@termix-ssh/plugin-sdk/backend";
import { startServer, type TestServer } from "./helpers";
import { csvCell } from "../../src/backend/routes";

let server: TestServer | null = null;

afterEach(async () => {
  vi.useRealTimers();
  await server?.close();
  server = null;
});

const connect = (
  overrides: Partial<PluginConnectPolicyInput> = {},
): PluginConnectPolicyInput => ({
  userId: "alice",
  hostId: 7,
  protocol: "ssh",
  purpose: "terminal",
  profile: "terminal",
  interactive: true,
  origin: "ssh-terminal",
  ...overrides,
});

async function policy(input: PluginConnectPolicyInput) {
  const provider = server!.mock.connectPolicyProviders[0];
  return provider.check(input);
}

async function markPrivileged(settings: Record<string, unknown> = {}) {
  await server!.mock.ctx.settings.setHost(7, "privileged", true);
  for (const [key, value] of Object.entries(settings)) {
    await server!.mock.ctx.settings.setHost(7, key, value);
  }
}

async function askAndApprove(hours = 2) {
  const asked = await server!.request("POST", "/requests", {
    user: "alice",
    body: { hostId: 7, hours, reason: "Fix the disk" },
  });
  expect(asked.status).toBe(200);
  const id = asked.body.request.id;
  const approved = await server!.request("POST", `/requests/${id}/approve`, {
    user: "bob",
    body: { comment: "ok" },
  });
  expect(approved.status).toBe(200);
  return id as number;
}

describe("connect policy", () => {
  it("lets every session through to a host that is not privileged", async () => {
    server = await startServer();
    expect(server.mock.connectPolicyProviders).toHaveLength(1);
    expect(await policy(connect())).toEqual({ decision: "allow" });
  });

  it("asks for a request on a privileged host", async () => {
    server = await startServer();
    await markPrivileged();
    expect(await policy(connect())).toMatchObject({
      decision: "request",
      requestTab: "access",
    });
  });

  it("lets background work through only when the host allows it", async () => {
    server = await startServer();
    await markPrivileged({ allowBackground: true });
    expect(
      await policy(connect({ interactive: false, profile: "background" })),
    ).toEqual({ decision: "allow" });
    expect(await policy(connect())).toMatchObject({ decision: "request" });
  });

  it("allows break glass access and alerts approvers", async () => {
    server = await startServer({
      permissions: [
        "privileged-access.request",
        "privileged-access.approve",
        "privileged-access.bypass",
      ],
    });
    await markPrivileged();
    expect(await policy(connect())).toEqual({ decision: "allow" });
    await vi.waitFor(() =>
      expect(
        server!.mock.notifications.map((entry) => entry.notification),
      ).toContainEqual(
        expect.objectContaining({
          category: "privileged-access.bypass",
          severity: "critical",
        }),
      ),
    );
    expect(server.mock.audits).toContainEqual(
      expect.objectContaining({ action: "privileged_access_bypassed" }),
    );
  });
});

describe("requests", () => {
  it("grants access after someone else approves", async () => {
    server = await startServer();
    await markPrivileged();
    await askAndApprove();
    expect(await policy(connect())).toEqual({ decision: "allow" });
    // Only alice got access.
    expect(await policy(connect({ userId: "bob" }))).toMatchObject({
      decision: "request",
    });
    const notified = server.mock.notifications.map((n) => n.notification);
    expect(notified).toContainEqual(
      expect.objectContaining({ category: "privileged-access.request" }),
    );
    expect(notified).toContainEqual(
      expect.objectContaining({
        category: "privileged-access.approved",
        audience: { userId: "alice" },
      }),
    );
  });

  it("never lets someone approve their own request", async () => {
    server = await startServer();
    await markPrivileged();
    const asked = await server.request("POST", "/requests", {
      body: { hostId: 7, hours: 1, reason: "x" },
    });
    const self = await server.request(
      "POST",
      `/requests/${asked.body.request.id}/approve`,
      { user: "alice", body: {} },
    );
    expect(self.status).toBe(403);
    expect(await policy(connect())).toMatchObject({ decision: "request" });
  });

  it("checks the host's limits", async () => {
    server = await startServer();
    await markPrivileged({ maxHours: 2, requireTicket: true });
    const tooLong = await server.request("POST", "/requests", {
      body: { hostId: 7, hours: 5, reason: "x", ticket: "T-1" },
    });
    expect(tooLong.status).toBe(400);
    const noTicket = await server.request("POST", "/requests", {
      body: { hostId: 7, hours: 1, reason: "x" },
    });
    expect(noTicket.status).toBe(400);
    const noReason = await server.request("POST", "/requests", {
      body: { hostId: 7, hours: 1, ticket: "T-1" },
    });
    expect(noReason.status).toBe(400);
  });

  it("refuses a request for a host that is not privileged", async () => {
    server = await startServer();
    const res = await server.request("POST", "/requests", {
      body: { hostId: 7, hours: 1, reason: "x" },
    });
    expect(res.status).toBe(400);
  });

  it("only lets the host's approver roles decide", async () => {
    server = await startServer();
    await markPrivileged({ approverRoles: "dba" });
    server.db.sqlite
      .prepare("INSERT INTO roles (id, name) VALUES (?, ?)")
      .run(5, "dba");
    const asked = await server.request("POST", "/requests", {
      body: { hostId: 7, hours: 1, reason: "x" },
    });
    const id = asked.body.request.id;
    const denied = await server.request("POST", `/requests/${id}/approve`, {
      user: "bob",
      body: {},
    });
    expect(denied.status).toBe(403);
    server.db.sqlite
      .prepare("INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)")
      .run("bob", 5);
    const ok = await server.request("POST", `/requests/${id}/approve`, {
      user: "bob",
      body: {},
    });
    expect(ok.status).toBe(200);
  });

  it("revoking ends the user's open sessions on that host", async () => {
    const ended: string[] = [];
    server = await startServer({
      services: {
        "sessions.live#ssh": {
          listForUser: (userId: string) =>
            userId === "alice"
              ? [
                  { id: "s-1", hostId: 7 },
                  { id: "s-2", hostId: 8 },
                ]
              : [],
          ownerEndSession: async (id: string) => {
            ended.push(id);
          },
        },
      },
    });
    await markPrivileged();
    const id = await askAndApprove();
    const revoked = await server.request("POST", `/requests/${id}/end`, {
      user: "bob",
      body: {},
    });
    expect(revoked.body.request.status).toBe("revoked");
    expect(ended).toEqual(["s-1"]);
    expect(await policy(connect())).toMatchObject({ decision: "request" });
  });

  it("expires access when the time runs out", async () => {
    server = await startServer();
    await markPrivileged();
    await askAndApprove(1);
    server.db.sqlite
      .prepare(
        "UPDATE p_privileged_access_requests SET expires_at = ? WHERE status = 'approved'",
      )
      .run(new Date(Date.now() - 1000).toISOString());
    const { createRequestStore } = await import("../../src/backend/store.js");
    const { createAccessService } = await import("../../src/backend/access.js");
    const { createWorkflow } = await import("../../src/backend/workflow.js");
    const { requests } = await import("../../src/backend/tables.js");
    const ctx = server.mock.ctx;
    const store = createRequestStore(ctx.db, await ctx.db.define(requests));
    const access = createAccessService(ctx, store);
    await access.reloadGrants();
    expect(access.hasGrant("alice", 7)).toBe(false);
    await createWorkflow(ctx, store, access).sweep();
    expect((await store.all()).map((row) => row.status)).toEqual(["expired"]);
    expect(server.mock.audits).toContainEqual(
      expect.objectContaining({ action: "privileged_access_expired" }),
    );
  });

  it("expires a request nobody decided", async () => {
    server = await startServer();
    await markPrivileged();
    await server.mock.ctx.settings.set("pendingHours", 1);
    await server.request("POST", "/requests", {
      body: { hostId: 7, hours: 1, reason: "x" },
    });
    server.db.sqlite
      .prepare("UPDATE p_privileged_access_requests SET created_at = ?")
      .run(new Date(Date.now() - 2 * 3_600_000).toISOString());
    const { createRequestStore } = await import("../../src/backend/store.js");
    const { createAccessService } = await import("../../src/backend/access.js");
    const { createWorkflow } = await import("../../src/backend/workflow.js");
    const { requests } = await import("../../src/backend/tables.js");
    const ctx = server.mock.ctx;
    const store = createRequestStore(ctx.db, await ctx.db.define(requests));
    await createWorkflow(ctx, store, createAccessService(ctx, store)).sweep();
    expect((await store.all())[0].status).toBe("expired");
  });

  it("lists to decide only for approvers and exports a CSV", async () => {
    server = await startServer({
      permissions: ["privileged-access.request"],
    });
    expect(
      (await server.request("GET", "/requests?scope=pending")).status,
    ).toBe(403);
    await server.close();

    server = await startServer();
    await markPrivileged();
    await server.request("POST", "/requests", {
      body: { hostId: 7, hours: 1, reason: "=cmd()" },
    });
    const pending = await server.request("GET", "/requests?scope=pending", {
      user: "bob",
    });
    expect(pending.body.requests).toHaveLength(1);
    const csv = await server.request("GET", "/report.csv", { user: "bob" });
    expect(csv.status).toBe(200);
    expect(csv.text).toContain("'=cmd()");
  });
});

describe("csv cells", () => {
  it("quotes and defuses", () => {
    expect(csvCell('a,"b"')).toBe('"a,""b"""');
    expect(csvCell("+1")).toBe("'+1");
    expect(csvCell(null)).toBe("");
  });
});
