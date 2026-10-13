import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { App } from "antd";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import type { PersonalEnvironment } from "@opensoha/contracts/gen/ts/sohaapi";
import { AssistantWorkspace } from "@/assistant-workspace";
import { assistantApi } from "@/assistant-api";

vi.mock("@/assistant-api", () => ({ assistantApi: { workspaceRuntime: vi.fn(), guestToolsOperation: vi.fn(), runtime: vi.fn(), guestTools: vi.fn() } }));
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
afterEach(async () => {await act(async () => root.unmount());client.clear();node.remove();vi.unstubAllGlobals();});
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
