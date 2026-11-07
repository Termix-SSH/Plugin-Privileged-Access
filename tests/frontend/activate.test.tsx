import { afterEach, describe, expect, it, vi } from "vitest";
import { fireEvent, screen } from "@testing-library/react";
import type { PluginApiClient } from "@termix-ssh/plugin-sdk/frontend";
import {
  renderWithApp,
  type RenderedPluginApp,
} from "@termix-ssh/plugin-sdk/testing";
import type { PluginManifest } from "@termix-ssh/plugin-sdk/manifest";
import * as plugin from "../../src/frontend/index";
import manifestJson from "../../manifest.json";
import locales from "../../locales/en.json";

const manifest = manifestJson as unknown as PluginManifest;

let rendered: RenderedPluginApp | null = null;

afterEach(async () => {
  await rendered?.deactivate();
  rendered = null;
});

const PENDING = {
  id: 4,
  hostId: 7,
  hostName: "prod-db",
  userId: "alice",
  username: "alice",
  reason: "Fix the disk",
  ticket: "OPS-12",
  hours: 2,
  status: "pending",
  createdAt: "2026-11-05T10:00:00.000Z",
  decidedByName: null,
  decidedAt: null,
  comment: null,
  startsAt: null,
  expiresAt: null,
  endedAt: null,
};

function api(): PluginApiClient {
  return {
    get: vi.fn(async (url: string) => {
      if (url === "/hosts") {
        return {
          data: {
            hosts: [
              {
                id: 7,
                name: "prod-db",
                maxHours: 4,
                requireReason: true,
                requireTicket: false,
                accessUntil: null,
              },
            ],
          },
        };
      }
      if (url === "/summary") {
        return {
          data: { approver: true, pending: 1, latest: [PENDING], active: [] },
        };
      }
      return { data: { requests: [PENDING] } };
    }),
    post: vi.fn(async () => ({ data: { request: PENDING } })),
    put: vi.fn(async () => ({ data: {} })),
    patch: vi.fn(async () => ({ data: {} })),
    delete: vi.fn(async () => ({ data: {} })),
  } as unknown as PluginApiClient;
}

describe("privileged access frontend", () => {
  it("registers its tab, rail item and card", async () => {
    rendered = await renderWithApp(plugin, { manifest, locales, api: api() });
    expect(rendered.registered.tabs()).toEqual(["access"]);
    expect(rendered.registered.railItems()).toEqual([
      expect.objectContaining({ id: "access" }),
    ]);
    expect(rendered.registered.dashboardCards()).toEqual(["pending-access"]);
  });

  it("sends a request for the picked host", async () => {
    const client = api();
    rendered = await renderWithApp(plugin, {
      manifest,
      locales,
      permissions: ["privileged-access.request"],
      api: client,
    });
    rendered.renderTab("access", {
      tab: { id: "t1", type: "access", label: "Access", data: { hostId: 7 } },
    });
    await screen.findByText("Why you need access");
    const reason = document.querySelector("textarea")!;
    fireEvent.change(reason, { target: { value: "Fix the disk" } });
    fireEvent.click(screen.getAllByText("Ask for access").at(-1)!);
    await vi.waitFor(() =>
      expect(client.post).toHaveBeenCalledWith("/requests", {
        hostId: 7,
        hours: 1,
        reason: "Fix the disk",
        ticket: "",
      }),
    );
    expect(screen.queryByText("To decide")).toBeNull();
  });

  it("lets an approver approve after a confirm", async () => {
    const client = api();
    rendered = await renderWithApp(plugin, {
      manifest,
      locales,
      permissions: ["privileged-access.request", "privileged-access.approve"],
      api: client,
    });
    rendered.renderTab("access");
    fireEvent.click(await screen.findByText("To decide"));
    expect(await screen.findByText("OPS-12")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Approve" }));
    const buttons = await screen.findAllByText("Approve");
    fireEvent.click(buttons[buttons.length - 1]);
    await vi.waitFor(() =>
      expect(client.post).toHaveBeenCalledWith("/requests/4/approve", {
        comment: undefined,
      }),
    );
  });

  it("shows waiting requests on the dashboard card", async () => {
    rendered = await renderWithApp(plugin, { manifest, locales, api: api() });
    rendered.renderDashboardCard("pending-access");
    expect(await screen.findByText("prod-db")).toBeTruthy();
    fireEvent.click(screen.getByText("prod-db"));
    expect(rendered.shellCalls).toContainEqual({
      method: "openSingletonTab",
      args: ["access"],
    });
  });
});
