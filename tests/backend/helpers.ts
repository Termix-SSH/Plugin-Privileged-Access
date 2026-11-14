import http from "node:http";
import type { AddressInfo } from "node:net";
import { fileURLToPath } from "node:url";
import express, { type Router } from "express";
import {
  createMockCtx,
  createTestDb,
  type MockPluginContext,
  type TestDb,
} from "@termix-ssh/plugin-sdk/testing";
import type { PluginHostSummary } from "@termix-ssh/plugin-sdk/backend";
import type { PluginManifest } from "@termix-ssh/plugin-sdk/manifest";
import manifestJson from "../../manifest.json";

export const pluginDir = fileURLToPath(new URL("../..", import.meta.url));
export const manifest = manifestJson as unknown as PluginManifest;

export function host(
  overrides: Partial<PluginHostSummary> = {},
): PluginHostSummary {
  return {
    id: 7,
    userId: "owner",
    name: "prod-db",
    ip: "10.0.0.5",
    port: 22,
    username: "root",
    tags: null,
    folder: null,
    authType: "password",
    ...overrides,
  };
}

export interface TestServer {
  db: TestDb;
  mock: MockPluginContext;
  request: (
    method: string,
    path: string,
    options?: { user?: string; body?: unknown },
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
  ) => Promise<{ status: number; body: any; text: string }>;
  close: () => Promise<void>;
}

export async function startServer(
  options: {
    permissions?: string[];
    services?: Record<string, object>;
    hosts?: PluginHostSummary[];
  } = {},
): Promise<TestServer> {
  const db = await createTestDb(pluginDir);
  for (const user of ["owner", "alice", "bob"]) {
    db.sqlite
      .prepare("INSERT INTO users (id, username) VALUES (?, ?)")
      .run(user, user);
  }

  let router: Router | null = null;
  const mock = createMockCtx({
    sandbox: true,
    pluginId: manifest.id,
    manifest,
    capabilities: manifest.capabilities,
    db: db.database,
    router: () => (router = express.Router()),
    permissions: options.permissions ?? [
      "privileged-access.request",
      "privileged-access.approve",
    ],
    hosts: options.hosts ?? [host()],
    services: options.services,
  });

  const { activate } = await import("../../src/backend/index.js");
  await activate(mock.ctx);

  const app = express();
  app.use(express.json());
  app.use((req, _res, next) => {
    mock.setActor(req.header("x-test-user") ?? undefined);
    next();
  });
  app.use((req, res, next) => router!(req, res, next));
  const server = http.createServer(app);
  await new Promise<void>((resolve) => server.listen(0, resolve));
  const { port } = server.address() as AddressInfo;

  return {
    db,
    mock,
    async request(method, path, { user = "alice", body } = {}) {
      const response = await fetch(`http://127.0.0.1:${port}${path}`, {
        method,
        headers: {
          "x-test-user": user,
          ...(body !== undefined ? { "content-type": "application/json" } : {}),
        },
        body: body !== undefined ? JSON.stringify(body) : undefined,
      });
      const text = await response.text();
      let parsed: unknown = null;
      try {
        parsed = text ? JSON.parse(text) : null;
      } catch {
        parsed = null;
      }
      return { status: response.status, body: parsed, text };
    },
    async close() {
      for (const dispose of [...mock.disposals].reverse()) await dispose();
      await new Promise<void>((resolve) => server.close(() => resolve()));
      db.close();
    },
  };
}
