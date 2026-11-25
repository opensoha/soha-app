import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { ConfigProvider } from "antd";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import {
  assistantRequest,
  meshNativeDelegation,
  requestResponse,
} from "@/api";
import { AssistantMeshDelegations } from "@/assistant-mesh-delegations";
import { meshApi } from "@/assistant-mesh-api";
import { useAppStore } from "@/store";
import type { HostState } from "@/types";

vi.mock("@/api", () => ({
  ApiError: class ApiError extends Error {
    constructor(
      readonly status: number,
      readonly code: string,
      message: string,
    ) {
      super(message);
      this.name = "ApiError";
    }
  },
  assistantRequest: vi.fn(),
  requestResponse: vi.fn(),
  meshNativeDelegation: vi.fn(),
  setAccessToken: vi.fn(),
  invalidateServerRequests: vi.fn(),
}));

vi.mock("@/assistant-mesh-api", () => ({
  meshApi: { search: vi.fn() },
}));

const json = (body: unknown) => new Response(JSON.stringify(body));
const delegation = {
  id: "delegation-1",
  callerId: "caller-1",
  callerName: "张三",
  ownerId: "user-1",
  ownerName: "我",
  capability: "desktop.os-version.v1",
  field: "productVersion" as const,
  inputHash: "abcdef1234567890",
  status: "awaiting_owner_approval" as const,
  createdAt: "2026-11-21T01:00:00Z",
  expiresAt: "2026-11-21T02:00:00Z",
};

const host = (platform: string): HostState => ({
  serverUrl: "https://soha.example",
  configurationSource: "saved",
  managedByEnvironment: false,
  app: {
    name: "Soha",
    version: "1.0.0",
    platform,
    arch: "arm64",
    logDirectory: "/tmp",
    updateSupported: false,
  },
});

let root: Root;
let node: HTMLDivElement;
let client: QueryClient;
let inbox: unknown[];

beforeEach(() => {
  vi.clearAllMocks();
  inbox = [delegation];
  vi.stubGlobal(
    "ResizeObserver",
    class {
      observe = vi.fn();
      unobserve = vi.fn();
      disconnect = vi.fn();
    },
  );
  vi.mocked(requestResponse).mockImplementation(async (path) =>
    json({
      items: String(path).includes("direction=inbox") ? inbox : [],
    }),
  );
  vi.mocked(meshApi.search).mockResolvedValue([]);
  node = document.createElement("div");
  document.body.append(node);
  root = createRoot(node);
  client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
});

afterEach(async () => {
  await act(async () => root.unmount());
  client.clear();
  node.remove();
  useAppStore.setState({ host: null });
  vi.unstubAllGlobals();
});

async function settle() {
  for (let index = 0; index < 2; index += 1) {
    await act(async () => {
      await new Promise((resolve) => setTimeout(resolve, 80));
    });
  }
}

async function render() {
  await act(async () => {
    root.render(
      <ConfigProvider>
        <QueryClientProvider client={client}>
          <AssistantMeshDelegations owner="assistant-1" userId="user-1" />
        </QueryClientProvider>
      </ConfigProvider>,
    );
  });
  await settle();
}

function button(label: string) {
  const found = Array.from(document.querySelectorAll("button")).find(
    (item) => item.textContent?.trim() === label,
  );
  expect(found).toBeDefined();
  return found!;
}

it("keeps approval in the macOS App and still allows decline on the Web", async () => {
  vi.mocked(assistantRequest).mockResolvedValue({
    ...delegation, status: "declined",
  });
  useAppStore.setState({ host: host("web") });
  await render();

  expect(document.body.textContent).toContain("批准需在 macOS App 中完成");
  expect(
    Array.from(document.querySelectorAll("button")).some(
      (item) => item.textContent?.trim() === "批准并在本机预览",
    ),
  ).toBe(false);

  await act(async () => button("拒绝请求").click());
  await settle();
  expect(assistantRequest).toHaveBeenCalledWith(
    "/copilot/assistant-mesh/delegations/delegation-1/decline",
    { method: "POST", body: "{}" },
  );
});

it("reports an unavailable preview after a native cold restart and keeps decline", async () => {
  vi.mocked(meshNativeDelegation).mockResolvedValue({ state: "unavailable" });
  inbox = [{ ...delegation, status: "awaiting_confirmation" }];
  useAppStore.setState({ host: host("darwin") });
  await render();

  await act(async () => button("查看本机预览").click());
  await settle();

  expect(meshNativeDelegation).toHaveBeenCalledWith("preview", {
    id: "delegation-1",
  });
  expect(document.body.textContent).toContain("当前原生环境不可用");
  expect(button("拒绝请求")).toBeDefined();
});

it("shows a result only after completion", async () => {
  inbox = [
    { ...delegation, status: "completed", result: "1.2.3" },
    {
      ...delegation,
      id: "delegation-2",
      status: "failed",
      result: "must-not-render",
    },
  ];
  useAppStore.setState({ host: host("darwin") });
  await render();

  expect(document.body.textContent).toContain("1.2.3");
  expect(document.body.textContent).not.toContain("must-not-render");
  expect(document.body.textContent).toContain("失败");
});
