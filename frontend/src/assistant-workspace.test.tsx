import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { App } from "antd";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import type { PersonalEnvironment } from "@opensoha/contracts/gen/ts/sohaapi";
import { AssistantWorkspace } from "@/assistant-workspace";
import { assistantApi } from "@/assistant-api";
import { deployWorkspaceHostedApp, listMyHostedApps, searchAppHostingAudience } from "@/api";
import { openBrowserURL } from "@/native/host";
import { useAppStore } from "@/store";

vi.mock("@/assistant-api", () => ({ assistantApi: { workspaceRuntime: vi.fn(), guestToolsOperation: vi.fn(), runtime: vi.fn(), guestTools: vi.fn() } }));
vi.mock("@/api", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/api")>()),
  deployWorkspaceHostedApp: vi.fn(),
  listMyHostedApps: vi.fn().mockResolvedValue([]),
  searchAppHostingAudience: vi.fn().mockResolvedValue({ users: [], teams: [] }),
}));
vi.mock("@/native/host", () => ({ openBrowserURL: vi.fn().mockResolvedValue(undefined) }));
let root: Root;
let node: HTMLDivElement;
let client: QueryClient;
const environment: PersonalEnvironment = {assistantId: "assistant-one", state: "ready", version: 7, dataInitialized: true, expiresAt: "2099-01-01T00:00:00Z"};
beforeEach(() => {
  vi.clearAllMocks();
  vi.stubGlobal("ResizeObserver", class {observe = vi.fn();unobserve = vi.fn();disconnect = vi.fn();});
  vi.mocked(assistantApi.workspaceRuntime).mockResolvedValue({assistantId: environment.assistantId, environmentVersion: 7});
  node = document.createElement("div");document.body.appendChild(node);root = createRoot(node);
  client = new QueryClient({defaultOptions: {queries: {retry: false}, mutations: {retry: false}}});
});
afterEach(async () => {await act(async () => root.unmount());client.clear();node.remove();useAppStore.setState({bootstrap: null, host: null});vi.unstubAllGlobals();});
function setWorkspaceStore(permissionKeys: string[]) {
  const principal = { userId: "user-one", userName: "alice", email: "", roles: [], teams: [], projects: [], tags: [] };
  useAppStore.setState({
    host: {
      serverUrl: "https://soha.example.com",
      configurationSource: "saved",
      managedByEnvironment: false,
      app: { name: "Soha", version: "test", platform: "darwin", arch: "arm64", logDirectory: "/tmp", updateSupported: false },
    },
    bootstrap: {
      user: principal,
      currentUser: principal,
      branding: {},
      permissionSnapshot: { permissionKeys },
    },
    locale: "zh_CN",
  });
}
function button(label: string) {const b = Array.from(document.querySelectorAll("button")).find(v => v.textContent?.trim() === label);expect(b).toBeDefined();return b!;}
async function click(e: HTMLElement) {await act(async () => {e.click();await new Promise(r => setTimeout(r,25));});await act(async () => {await new Promise(r => setTimeout(r,25));});}
async function open() {await act(async () => {root.render(<App><QueryClientProvider client={client}><AssistantWorkspace owner="user-one" environment={environment} onRefresh={() => {}} /></QueryClientProvider></App>);});await click(button("打开个人工作空间"));}
it("pauses execution when the server cannot confirm the shared workspace", async () => {
  vi.mocked(assistantApi.workspaceRuntime).mockRejectedValue(new Error("unavailable"));
  await open();
  expect(document.body.textContent).toContain("工作空间读取失败，操作已暂停");
  expect(button("执行命令").disabled).toBe(true);
  expect(button("接通执行能力").disabled).toBe(true);
  expect(assistantApi.runtime).not.toHaveBeenCalled();
});
it("rejects stale browser pointer input using the same generation fence as Web", async () => {
  vi.mocked(assistantApi.workspaceRuntime).mockResolvedValue({assistantId: environment.assistantId, environmentVersion: 7,
    latest: {id: "original", kind: "browser", status: "succeeded", assistantId: environment.assistantId, environmentVersion: 7, browser: {controlId: "control", generation: 1, instanceId: "instance", width: 800, height: 600, jpegBase64: "AA=="}},
    browserControl: {controlId: "control", generation: 2, owner: "user", instanceId: "instance", expiresAt: "2099-01-01T00:00:00Z"}});
  await open();await click(Array.from(document.querySelectorAll<HTMLElement>('[role="tab"]')).find(e => e.textContent === "浏览器")!);
  const pointer = document.querySelector<HTMLButtonElement>('button[aria-label="在浏览器画面中点击"]')!;
  expect(pointer).not.toBeNull();expect(pointer.disabled).toBe(true);
  expect(document.body.textContent).toContain("保留的观察画面");
  expect(assistantApi.runtime).not.toHaveBeenCalled();
});
it("hides workspace publish tab when caller lacks apphosting.apps.publish", async () => {
  setWorkspaceStore(["observe.ai.chat"]);
  await open();
  const publishTab = Array.from(document.querySelectorAll<HTMLElement>('[role="tab"]')).find(
    (e) => e.textContent === "发布应用",
  );
  expect(publishTab).toBeUndefined();
});
it("publishes a workspace directory directly via server-side bundling and displays pending approval receipt", async () => {
  setWorkspaceStore(["observe.ai.chat", "apphosting.apps.publish"]);
  vi.mocked(searchAppHostingAudience).mockResolvedValue({
    teams: [{ id: "team-admin", name: "行政部" }],
    users: [{ id: "user-wang", username: "wangwu", displayName: "王五", department: "行政部" }],
  });
  vi.mocked(deployWorkspaceHostedApp).mockResolvedValue({
    created: true,
    app: {
      id: "hosted-ws-1",
      name: "排班小工具",
      kind: "static",
      dnsLabel: "schedule-tool-a1b2",
      host: "schedule-tool-a1b2.apps.example.com",
      url: "https://schedule-tool-a1b2.apps.example.com/",
      spaFallback: true,
      ownerUserId: "user-one",
      maintainerUserIds: [],
      visibility: { mode: "private" },
      pendingVisibilityApproval: {
        id: "approval-1",
        appId: "hosted-ws-1",
        appName: "排班小工具",
        appDnsLabel: "schedule-tool-a1b2",
        requesterUserId: "user-one",
        currentVisibility: { mode: "private" },
        requestedVisibility: { mode: "organization" },
        baseRouteGeneration: 1,
        policyVersion: 1,
        status: "pending",
        createdAt: "2026-11-21T00:00:00Z",
        updatedAt: "2026-11-21T00:00:00Z",
      },
      status: "online",
      routeGeneration: 1,
      createdAt: "2026-11-21T00:00:00Z",
      updatedAt: "2026-11-21T00:00:00Z",
    },
    revision: {
      id: "rev-ws-1",
      appId: "hosted-ws-1",
      revisionNumber: 1,
      kind: "static",
      status: "ready",
      bundleSha256: "b".repeat(64),
      fileCount: 4,
      totalBytes: 4096,
      spaFallback: true,
      createdBy: "user-one",
      createdAt: "2026-11-21T00:00:00Z",
    },
  });

  await open();
  await click(Array.from(document.querySelectorAll<HTMLElement>('[role="tab"]')).find(e => e.textContent === "发布应用")!);

  const pathInput = document.querySelector<HTMLInputElement>('input[aria-label="工作空间相对路径"]')!;
  await act(async () => {
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")?.set?.call(pathInput, "schedule-tool");
    pathInput.dispatchEvent(new Event("input", { bubbles: true }));
  });

  await click(button("发布为托管应用"));

  const nameInput = document.querySelector<HTMLInputElement>('input[aria-label="作品名称"]')!;
  expect(nameInput.value).toBe("schedule-tool");
  await act(async () => {
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")?.set?.call(nameInput, "排班小工具");
    nameInput.dispatchEvent(new Event("input", { bubbles: true }));
  });

  // Switch to 指定部门或个人 first to verify audience candidates load, then 全公司 with reason
  const selectedSeg = Array.from(document.querySelectorAll<HTMLElement>(".ant-segmented-item")).find(
    (item) => item.textContent?.includes("指定部门或个人"),
  )!;
  await click(selectedSeg);
  expect(searchAppHostingAudience).toHaveBeenCalled();
  expect(document.body.textContent).toContain("行政部");
  expect(document.body.textContent).toContain("王五");

  const orgSeg = Array.from(document.querySelectorAll<HTMLElement>(".ant-segmented-item")).find(
    (item) => item.textContent === "全公司",
  )!;
  await click(orgSeg);

  const reasonInput = document.querySelector<HTMLTextAreaElement>('textarea[aria-label="全公司公开申请说明"]')!;
  await act(async () => {
    Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, "value")?.set?.call(reasonInput, "全员排班查询");
    reasonInput.dispatchEvent(new Event("input", { bubbles: true }));
  });

  await click(button("立即发布"));

  expect(listMyHostedApps).toHaveBeenCalled();
  expect(deployWorkspaceHostedApp).toHaveBeenCalledTimes(1);
  expect(deployWorkspaceHostedApp).toHaveBeenCalledWith(
    expect.objectContaining({
      name: "排班小工具",
      visibility: { mode: "organization" },
      visibilityReason: "全员排班查询",
      source: {
        kind: "personal_environment",
        sourcePath: "schedule-tool",
        assistantId: "assistant-one",
        environmentVersion: 7,
      },
      idempotencyKey: expect.stringMatching(/^[0-9a-f-]{36}$/i),
    }),
  );
  expect(assistantApi.runtime).not.toHaveBeenCalled();

  expect(document.body.textContent).toContain("全公司公开待管理员审批，当前维持私有/原范围");
  expect(document.body.textContent).toContain("https://schedule-tool-a1b2.apps.example.com/");

  await click(button("在浏览器打开应用"));
  expect(openBrowserURL).toHaveBeenCalledWith("https://schedule-tool-a1b2.apps.example.com/");

  const writeText = vi.fn().mockResolvedValue(undefined);
  Object.defineProperty(navigator, "clipboard", {
    configurable: true,
    value: { writeText },
  });
  await click(button("复制链接"));
  expect(writeText).toHaveBeenCalledWith("https://schedule-tool-a1b2.apps.example.com/");
});
it("queues a dynamic workspace deployment without exposing a live link", async () => {
  setWorkspaceStore(["observe.ai.chat", "apphosting.apps.publish"]);
  const timestamp = "2026-11-21T00:00:00Z";
  vi.mocked(deployWorkspaceHostedApp).mockResolvedValue({
    created: true,
    app: {
      id: "hosted-dynamic",
      name: "forms",
      kind: "dynamic",
      dnsLabel: "forms-a1b2",
      host: "forms-a1b2.apps.example.com",
      url: "https://forms-a1b2.apps.example.com/",
      spaFallback: false,
      ownerUserId: "user-one",
      maintainerUserIds: [],
      visibility: { mode: "private" },
      status: "draft",
      routeGeneration: 1,
      createdAt: timestamp,
      updatedAt: timestamp,
    },
    revision: {
      id: "rev-queued",
      appId: "hosted-dynamic",
      revisionNumber: 1,
      kind: "dynamic",
      status: "validating",
      bundleSha256: "b".repeat(64),
      fileCount: 2,
      totalBytes: 256,
      spaFallback: false,
      createdBy: "user-one",
      createdAt: timestamp,
    },
  });

  await open();
  await click(Array.from(document.querySelectorAll<HTMLElement>('[role="tab"]')).find(e => e.textContent === "发布应用")!);
  const pathInput = document.querySelector<HTMLInputElement>('input[aria-label="工作空间相对路径"]')!;
  await act(async () => {
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")?.set?.call(pathInput, "forms");
    pathInput.dispatchEvent(new Event("input", { bubbles: true }));
  });
  await click(button("发布为托管应用"));
  const dynamicOption = Array.from(document.querySelectorAll<HTMLElement>(".ant-segmented-item")).find(
    (item) => item.textContent === "动态 HTTP 应用",
  )!;
  await click(dynamicOption);
  await click(button("立即发布"));

  expect(deployWorkspaceHostedApp).toHaveBeenCalledOnce();
  const [request] = vi.mocked(deployWorkspaceHostedApp).mock.calls[0];
  expect(request.kind).toBe("dynamic");
  expect(request.spaFallback).toBeUndefined();
  expect(request.source).toMatchObject({ kind: "personal_environment", sourcePath: "forms" });
  expect(document.body.textContent).toContain("已提交构建，版本就绪后会自动上线");
  expect(document.body.textContent).not.toContain("https://forms-a1b2.apps.example.com/");
});

it("updates an existing hosted app, filters non-deployable apps, and supports collaborator update without visibility/name mutation", async () => {
  setWorkspaceStore(["observe.ai.chat", "apphosting.apps.publish"]);
  const existingApp = {
    id: "hosted-existing-1",
    name: "周报收集器",
    description: "部门周报",
    kind: "static" as const,
    dnsLabel: "weekly-c3d4",
    host: "weekly-c3d4.apps.example.com",
    url: "https://weekly-c3d4.apps.example.com/",
    spaFallback: false,
    ownerUserId: "user-one",
    maintainerUserIds: [],
    visibility: { mode: "organization" as const },
    status: "online" as const,
    routeGeneration: 2,
    createdAt: "2026-11-21T00:00:00Z",
    updatedAt: "2026-11-21T00:00:00Z",
  };
  const offlineApp = {
    ...existingApp,
    id: "hosted-offline-1",
    name: "已下线应用",
    status: "offline" as const,
  };
  const collabApp = {
    ...existingApp,
    id: "hosted-collab-1",
    name: "同事主创看板",
    host: "collab-e5f6.apps.example.com",
    ownerUserId: "user-peer",
    maintainerUserIds: ["user-one"],
  };
  vi.mocked(listMyHostedApps).mockResolvedValue([existingApp, offlineApp, collabApp]);
  vi.mocked(deployWorkspaceHostedApp).mockResolvedValue({
    created: false,
    app: { ...existingApp, visibility: { mode: "private" }, routeGeneration: 3 },
    revision: {
      id: "rev-2",
      appId: "hosted-existing-1",
      revisionNumber: 2,
      kind: "static",
      status: "ready",
      bundleSha256: "d".repeat(64),
      fileCount: 2,
      totalBytes: 1024,
      spaFallback: false,
      createdBy: "user-one",
      createdAt: "2026-11-21T01:00:00Z",
    },
  });

  await open();
  await click(Array.from(document.querySelectorAll<HTMLElement>('[role="tab"]')).find(e => e.textContent === "发布应用")!);
  await click(button("发布为托管应用"));

  const updateSeg = Array.from(document.querySelectorAll<HTMLElement>(".ant-segmented-item")).find(
    (item) => item.textContent === "更新已有应用",
  )!;
  await click(updateSeg);

  const selectBox = document.querySelector<HTMLElement>('[aria-label="选择已有应用"]')!;
  await act(async () => {
    selectBox.dispatchEvent(new MouseEvent("mousedown", { bubbles: true }));
    await new Promise((r) => setTimeout(r, 25));
  });
  expect(document.body.textContent).not.toContain("已下线应用");

  // Collaborator target omits name & visibility in payload
  const collabOption = Array.from(document.querySelectorAll<HTMLElement>(".ant-select-item-option")).find(
    (item) => item.textContent?.includes("同事主创看板"),
  )!;
  await click(collabOption);
  expect(document.body.textContent).toContain("协作者发版模式");
  expect(document.querySelector('input[aria-label="作品名称"]')).toBeNull();

  // Switch to owned app and narrow visibility explicitly
  await act(async () => {
    selectBox.dispatchEvent(new MouseEvent("mousedown", { bubbles: true }));
    await new Promise((r) => setTimeout(r, 25));
  });
  const option = Array.from(document.querySelectorAll<HTMLElement>(".ant-select-item-option")).find(
    (item) => item.textContent?.includes("周报收集器"),
  )!;
  await click(option);

  const privateSeg = Array.from(document.querySelectorAll<HTMLElement>(".ant-segmented-item")).find(
    (item) => item.textContent === "仅自己",
  )!;
  await click(privateSeg);
  expect(document.body.textContent).toContain("保存后，被移除的同事搜不到作品");

  await click(button("立即发布"));
  expect(deployWorkspaceHostedApp).toHaveBeenCalledWith(
    expect.objectContaining({
      appId: "hosted-existing-1",
      name: "周报收集器",
      visibility: { mode: "private" },
      source: {
        kind: "personal_environment",
        sourcePath: ".",
        assistantId: "assistant-one",
        environmentVersion: 7,
      },
    }),
  );
  expect(document.body.textContent).toContain("托管应用已更新版本");
});
