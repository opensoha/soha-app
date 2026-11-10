import { StyleProvider, createCache } from "@ant-design/cssinjs";
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { App, ConfigProvider } from "antd";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { ApiError } from "@/api";
import { AssistantPage } from "@/assistant";
import { assistantApi, streamAssistant } from "@/assistant-api";
import { selectAssistantOwner, useAppStore } from "@/store";
import * as imageHelpers from "@/assistant-avatar-image";
import {
  readPendingRequests,
  savePendingRequest,
} from "@/assistant-request-recovery";

vi.mock("@/assistant-api", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/assistant-api")>()),
  assistantApi: {
    chatMain: vi.fn().mockResolvedValue({id: "chat-main"}),
    session: vi.fn().mockImplementation(async (id: string, personal: boolean) => {
      if (personal && id === "main") return { id, title: "主聊天", metadata: { conversationKind: "personal_main" } };
      if (personal && id === "side") return { id, title: "发布方案", metadata: { conversationKind: "personal_side" } };
      if (!personal && id === "chat-main") return { id, title: "普通 Chat", metadata: { conversationKind: "main" } };
      return null;
    }),
    chatSessions: vi.fn().mockResolvedValue([{id: "chat-main", title: "普通 Chat", metadata: {conversationKind: "main"}}]),
    chatTasks: vi.fn().mockResolvedValue([]),
    chatSide: vi.fn(),
    runtimeProfiles: vi.fn().mockResolvedValue([]),
    selectRuntimeProfile: vi.fn(),
    access: vi
      .fn()
      .mockResolvedValue({ userId: "user-1", status: "approved", version: 1 }),
    requestAccess: vi.fn(),
    environmentTemplates: vi.fn().mockResolvedValue([]),
    changeEnvironment: vi.fn(),
    deleteEnvironmentData: vi.fn(),
    exportEnvironmentData: vi.fn().mockResolvedValue(null),
    environment: vi.fn().mockResolvedValue({
      assistantId: "assistant-1",
      state: "unprovisioned",
      version: 0,
      dataInitialized: false,
    }),
    catalog: vi.fn().mockResolvedValue({
      modelOptions: [{ publicModel: "model-A", reasoningEfforts: [] }],
      adapters: [],
      dataSources: [
        {
          id: "metrics-source",
          name: "Prometheus",
          enabled: true,
          sourceKind: "metrics",
          mcpAdapter: "metrics.v1",
          backendType: "prometheus",
        },
        {
          id: "trace-source",
          name: "SkyWalking",
          enabled: true,
          sourceKind: "traces",
          mcpAdapter: "traces.v1",
          backendType: "skywalking",
        },
      ],
      analysisProfiles: [
        {
          id: "root-profile",
          name: "发布根因模板",
          enabled: true,
          mode: "root_cause",
        },
      ],
    }),
    metrics: vi
      .fn()
      .mockResolvedValue([
        { key: "latency_p95", label: "P95 延迟", available: true },
      ]),
    knowledgeBases: vi
      .fn()
      .mockResolvedValue([
        { id: "kb-authorized", name: "运行手册", status: "active" },
      ]),
    memories: vi.fn().mockResolvedValue([
      {
        id: "memory-1",
        ownerType: "user",
        ownerId: "user-1",
        fact: "发布前检查",
        status: "active",
        sourceType: "explicit_user",
        policyId: "personal",
        policyVersion: "1",
        expiresAt: new Date(Date.now() + 86400000).toISOString(),
      },
    ]),
    saveMemoryPolicy: vi.fn(),
    memoryPolicies: vi.fn().mockResolvedValue([
      {
        id: "personal",
        version: "1",
        enabled: true,
        explicitWriteOnly: true,
        ownerTypes: ["user"],
        defaultTtl: 86400000000000,
      },
    ]),
    saveMemory: vi.fn().mockImplementation(async (input) => input.record),
    deleteMemory: vi.fn(),
    inspections: vi.fn().mockResolvedValue([
      {
        id: "inspection-done",
        status: "completed",
        completedAt: "2026-10-08T00:00:00Z",
        summary: "真实巡检记录",
      },
      { id: "inspection-running", status: "running", summary: "未完成巡检" },
    ]),
    ensure: vi.fn().mockResolvedValue({
      id: "assistant-1",
      name: "小苏",
      mainSessionId: "main",
    }),
    sessions: vi.fn().mockResolvedValue([
      { id: "main", title: "主聊天", metadata: { conversationKind: "main" } },
      { id: "side", title: "发布方案" },
    ]),
    messages: vi
      .fn()
      .mockResolvedValue([
        { id: "m1", sessionId: "main", role: "assistant", content: "欢迎回来" },
      ]),
    tasks: vi.fn().mockResolvedValue([
      {
        id: "task-side",
        sessionId: "side",
        status: "running",
        providerKind: "hermes",
        input: { question: "整理发布报告" },
        analysisArtifacts: [
          {
            kind: "report",
            title: "发布报告",
            summary: "已保存的成果",
            dataSourceSnapshot: { content: "报告正文" },
          },
        ],
      },
    ]),
    findRequest: vi
      .fn()
      .mockRejectedValue(new Error("Request not yet visible")),
    artifacts: vi.fn().mockResolvedValue([
      {
        id: "message:side:0",
        sessionId: "side",
        messageId: "side-reply",
        createdAt: "2026-10-06T08:00:00Z",
        artifact: {
          kind: "report",
          runId: "report-1",
          title: "旁聊直接生成的报告",
          summary: "跨话题成果",
          dataSourceSnapshot: { content: "报告正文" },
        },
      },
    ]),
    rename: vi.fn(),
    side: vi.fn(),
    cancel: vi.fn(),
    events: vi.fn(),
    resume: vi.fn(),
    approvals: vi.fn(),
    decide: vi.fn(),
  },
  streamAssistant: vi.fn(),
}));

let root: Root | undefined;
let node: HTMLDivElement | undefined;
let client: QueryClient | undefined;
beforeAll(() => {
  vi.stubGlobal(
    "ResizeObserver",
    class {
      observe = vi.fn();
      unobserve = vi.fn();
      disconnect = vi.fn();
    },
  );
});
afterEach(async () => {
  await act(async () => root?.unmount());
  node?.remove();
  client?.clear();
  useAppStore.setState({ bootstrap: null, host: null });
  vi.clearAllMocks();
  localStorage.clear();
});

async function render(
  canChat: boolean,
  permissions: string[] = [],
  entry = "/",
  ordinary = false,
) {
  const principal = {
    userId: "user-1",
    userName: "tester",
    email: "",
    roles: [],
    teams: [],
    projects: [],
    tags: [],
  };
  useAppStore.setState({
    bootstrap: {
      user: principal,
      currentUser: principal,
      branding: {},
      permissionSnapshot: {
        permissionKeys: canChat ? ["observe.ai.chat", ...permissions] : [],
      },
    },
  });
  node = document.createElement("div");
  document.body.appendChild(node);
  root = createRoot(node);
  // DOM interaction tests do not measure CSS/layout. Keep generated styles
  // outside the document so jsdom does not rematch every rule on each event.
  const interactionStyles = document.createElement("div");
  const interactionStyleCache = createCache();
  client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  await act(async () => {
    root!.render(
      <StyleProvider container={interactionStyles} cache={interactionStyleCache}>
        <QueryClientProvider client={client!}>
          <ConfigProvider>
            <App>
              <MemoryRouter initialEntries={[entry]}>
                <AssistantPage ordinary={ordinary} />
              </MemoryRouter>
            </App>
          </ConfigProvider>
        </QueryClientProvider>
      </StyleProvider>,
    );
  });
  await settleQueries();
  return node;
}

async function settleQueries() {
  for (let attempt = 0, stable = 0; attempt < 40 && stable < 2; attempt++) {
    await act(async () => {
      await new Promise((resolve) => setTimeout(resolve, 10));
    });
    stable = client?.isFetching() ? 0 : stable + 1;
  }
}

async function click(label: string) {
  let button: HTMLButtonElement | undefined;
  for (let attempt = 0; attempt < 20 && !button; attempt++) {
    button = [
      ...document.body.querySelectorAll<HTMLButtonElement>("button"),
    ].find(
      (item) =>
        item.textContent?.replace(/\s/g, "") === label.replace(/\s/g, "") ||
        item.getAttribute("aria-label") === label,
    );
    if (!button)
      await act(async () => {
        await new Promise((resolve) => setTimeout(resolve, 10));
      });
  }
  expect(button).toBeTruthy();
  await act(async () => {
    button!.click();
  });
  await settleQueries();
}

function composerInput(element: HTMLElement) {
  return element.querySelector<HTMLTextAreaElement>('textarea[aria-label="给助手发消息"]')!;
}

async function enterMessage(element: HTMLElement, text: string) {
  const input = composerInput(element);
  await act(async () => {
    Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, "value")?.set?.call(input, text);
    input.dispatchEvent(new Event("input", { bubbles: true }));
  });
}

async function waitForAssistantText(element: HTMLElement, text: string) {
  for (
    let attempt = 0;
    attempt < 20 && !element.textContent?.includes(text);
    attempt++
  ) {
    await act(async () => {
      await new Promise((resolve) => setTimeout(resolve, 10));
    });
  }
  expect(element.textContent).toContain(text);
}

async function selectOption(label: string, text: string) {
  const select = document.body.querySelector<HTMLElement>(
    `[aria-label="${label}"]`,
  )!;
  expect(select).toBeTruthy();
  await act(async () => {
    select.dispatchEvent(new MouseEvent("mousedown", { bubbles: true }));
    select.dispatchEvent(
      new KeyboardEvent("keydown", { key: "ArrowDown", bubbles: true }),
    );
  });
  const findOption = () => [
    ...document.body.querySelectorAll<HTMLElement>(".ant-select-item-option"),
  ].find(
    (item) =>
      !item.closest(".ant-select-dropdown-hidden") &&
      (label === "模型"
        ? item.querySelector(".ant-select-item-option-content")?.textContent ===
          text
        : item.textContent?.includes(text)),
  );
  let option = findOption();
  for (let attempt = 0; attempt < 40 && !option; attempt++) {
    await act(async () => {
      await new Promise((resolve) => setTimeout(resolve, 5));
    });
    option = findOption();
  }
  expect(option).toBeTruthy();
  await act(async () => {
    option!.click();
  });
}

describe("personal assistant App", () => {
  it.each([false, true])("reads historical system reply runtime evidence (authoritative Run=%s)", async (hasRun) => {
    if (hasRun) {
      vi.mocked(assistantApi.chatTasks).mockResolvedValueOnce([{
        id: "old-run", sessionId: "chat-main", status: "completed", providerKind: "dsh",
        output: {
          runtimeHooks: [{ id: "tool-audit", version: "1", callId: "call-1", toolName: "metrics.read", outcome: "completed" }],
        },
      }] as never);
    }
    const previousMessages = vi.mocked(assistantApi.messages).getMockImplementation()!;
    vi.mocked(assistantApi.messages).mockResolvedValue([{
      id: "old-run:reply",
      sessionId: "chat-main",
      role: "system",
      content: "上一轮已取消。",
      createdAt: "2026-01-01T00:00:00Z",
      metadata: {
        source: "dsh-runtime",
        agentRunId: "old-run",
        runtimeAssembly: { profileId: "ops", revision: 3, status: "confirmed", assets: [] },
        runtimeHooks: [
          { id: "tool-audit", version: "1", callId: "call-1", toolName: "metrics.read", outcome: "unknown" },
          { id: "tool-audit", version: "1", callId: "call-2", toolName: "private upstream payload", outcome: "completed" },
        ],
        toolExecutions: [{ toolName: "change.request", output: { relatedIds: { approvalRequestId: "approval-1" } } }],
      },
    }]);
    try {
      const element = await render(true, ["ai.memory.view", "ai.memory.update", "ai.gateway.approvals.view"], "/", true);
      await waitForAssistantText(element, "ops · v3 · 1 条 Hook 记录");
      const systemReply = element.querySelector(".app-assistant-message.is-system");
      expect(systemReply?.textContent).not.toContain("引用回复");
      expect(systemReply?.textContent).not.toContain("保存为个人记忆");
      expect(assistantApi.approvals).not.toHaveBeenCalled();
      await click("查看本轮装配详情");
      expect(document.body.textContent).toContain(`tool-audit @ 1 · metrics.read · ${hasRun ? "已完成" : "结果未知"}`);
      expect(document.body.textContent).not.toContain("private upstream payload");
    } finally {
      vi.mocked(assistantApi.messages).mockImplementation(previousMessages);
    }
  });

  it("selects an authorized runtime profile and displays the saved version for the next Chat turn", async () => {
    vi.mocked(assistantApi.runtimeProfiles).mockResolvedValue([
      {
        id: "ops", name: "排障配置", scope: "chat", revision: 2, enabled: true, assets: [],
        modelPreferences: { publicModel: "ops-model", reasoningEffort: "high" },
      },
      { id: "private", name: "个人配置", scope: "heya", revision: 1, enabled: true, assets: [] },
    ]);
    vi.mocked(assistantApi.chatTasks).mockResolvedValueOnce([{
      id: "run-1", providerId: "dsh", providerKind: "dsh", capabilityId: "general",
      sessionId: "chat-main", status: "completed", timeoutSeconds: 10, createdBy: "user-1",
      queuedAt: "2026-01-01T00:00:00Z", createdAt: "2026-01-01T00:00:00Z", updatedAt: "2026-01-01T00:00:00Z",
      toolExecutions: [
        { id: "loaded", adapterId: "read-only", toolName: "skill_read_only_load", status: "completed", startedAt: "2026-01-01T00:00:00Z" },
        { id: "failed", adapterId: "catalog-only", toolName: "skill_catalog_only_load", status: "failed", startedAt: "2026-01-01T00:00:00Z" },
      ],
      runtimeAssembly: {
        profileId: "chat-default", revision: 1, status: "degraded",
        assets: [
          { kind: "skill", id: "checks", version: "2", status: "unavailable", code: "asset_unavailable" },
          { kind: "skill", id: "read-only", version: "2", status: "loaded" },
          { kind: "skill", id: "catalog-only", version: "2", status: "loaded" },
        ],
      },
    }]);
    const previous = vi.mocked(assistantApi.chatSessions).getMockImplementation()!;
    let current: Awaited<ReturnType<typeof assistantApi.chatMain>> = {
      id: "chat-main", title: "普通 Chat", createdBy: "user-1", createdAt: "2026-01-01T00:00:00Z",
      updatedAt: "2026-01-01T00:00:00Z", metadata: { conversationKind: "main" },
    };
    vi.mocked(assistantApi.chatSessions).mockImplementation(async () => [current]);
    vi.mocked(assistantApi.selectRuntimeProfile).mockImplementationOnce(async (id, profileId) => {
      current = { ...current, id, metadata: { ...current.metadata, runtimeProfileId: profileId } };
      return current;
    });
    try {
      const element = await render(true, [], "/", true);
      await selectOption("运行配置", "排障配置 · v2");
      expect(assistantApi.selectRuntimeProfile).toHaveBeenCalledExactlyOnceWith("chat-main", "ops");
      await waitForAssistantText(element, "运行配置已保存，下一轮生效。");
      expect(element.textContent).toContain("排障配置 · v2");
      expect(element.querySelector(".app-assistant-model-name")?.textContent).toBe("ops-model");
      expect(element.querySelector(".app-assistant-model-effort")?.textContent).toBe("深度");
      expect(document.body.textContent).not.toContain("个人配置");
      expect(element.textContent).toContain("已降级");
      await click("查看本轮装配详情");
      expect(document.body.textContent).toContain("chat-default · v1");
      expect(document.body.textContent).toContain("Skill · checks @ 2 · 指定版本不可用");
      expect(document.body.textContent).toContain("Skill · read-only @ 2 · 目录已注册 · 正文已加载");
      const catalogOnly = Array.from(document.querySelectorAll(".ant-popover .ant-typography"))
        .find((item) => item.textContent?.includes("catalog-only"));
      expect(catalogOnly?.textContent).toBe("Skill · catalog-only @ 2 · 目录已注册");
    } finally {
      vi.mocked(assistantApi.runtimeProfiles).mockResolvedValue([]);
      vi.mocked(assistantApi.chatSessions).mockImplementation(previous);
    }
  });

  it("keeps Chat locked after an uncertain profile save until the authoritative read succeeds", async () => {
    vi.mocked(assistantApi.runtimeProfiles).mockResolvedValueOnce([
      { id: "ops", name: "排障配置", scope: "chat", revision: 2, enabled: true, assets: [] },
    ]);
    vi.mocked(assistantApi.selectRuntimeProfile).mockRejectedValueOnce(new Error("lost PUT receipt"));
    vi.mocked(assistantApi.session).mockRejectedValueOnce(new Error("GET unavailable")).mockResolvedValueOnce({
      id: "chat-main", title: "普通 Chat",
      metadata: { conversationKind: "main", runtimeProfileId: "ops" },
    } as Awaited<ReturnType<typeof assistantApi.session>>);
    const element = await render(true, [], "/", true);
    await selectOption("运行配置", "排障配置 · v2");
    await waitForAssistantText(element, "运行配置保存未确认，读取会话失败。确认前暂停发送。");
    expect(composerInput(element).disabled).toBe(true);
    expect(assistantApi.session).toHaveBeenCalledExactlyOnceWith("chat-main", false);
    await click("重试读取会话");
    await waitForAssistantText(element, "运行配置已保存，下一轮生效。");
    expect(composerInput(element).disabled).toBe(false);
    expect(assistantApi.selectRuntimeProfile).toHaveBeenCalledExactlyOnceWith("chat-main", "ops");
    expect(element.textContent).toContain("排障配置 · v2");
  });

  it("refreshes Heya messages once when a polled Run reaches its terminal state", async () => {
    const run = { id: "final-reply-run", sessionId: "main", status: "running", providerKind: "dsh", executionOwner: "external" };
    vi.mocked(assistantApi.tasks).mockResolvedValueOnce([run] as never);
    vi.mocked(assistantApi.events).mockResolvedValue({
      items: [], nextSequence: 0, hasMore: false, resyncRequired: false,
    });
    const element = await render(true);
    const messagesBefore = vi.mocked(assistantApi.messages).mock.calls.length;
    vi.mocked(assistantApi.messages).mockResolvedValueOnce([{
      id: "final-reply", sessionId: "main", role: "assistant", content: "终态回复已持久化",
      createdAt: "2026-01-01T00:00:00Z", metadata: { agentRunId: run.id },
    }]);
    const key = ["assistant-tasks", selectAssistantOwner(useAppStore.getState()), false];
    await act(async () => client!.setQueryData(key, [{ ...run, status: "completed" }]));
    await waitForAssistantText(element, "终态回复已持久化");
    await act(async () => client!.setQueryData(key, [{ ...run, status: "completed", updatedAt: "2026-01-01T00:01:00Z" }]));
    await settleQueries();
    expect(assistantApi.messages).toHaveBeenCalledTimes(messagesBefore + 1);
  });

  it.each([false, true])("replaces an in-flight first message read on cold recovery of a terminal receipt (pending journal=%s)", async (hasJournal) => {
    const owner = JSON.stringify(["", "user-1"]);
    let releaseInitialMessages!: (messages: Awaited<ReturnType<typeof assistantApi.messages>>) => void;
    let releaseReceipt!: (run: Awaited<ReturnType<typeof assistantApi.findRequest>>) => void;
    if (hasJournal) {
      savePendingRequest(owner, "main", "cold-recovery");
      vi.mocked(assistantApi.tasks).mockResolvedValueOnce([]);
      vi.mocked(assistantApi.findRequest).mockImplementationOnce(() => new Promise((resolve) => {
        releaseReceipt = resolve;
      }));
    } else {
      vi.mocked(assistantApi.tasks).mockImplementationOnce(() => new Promise((resolve) => {
        releaseReceipt = (run) => resolve([run]);
      }));
    }
    vi.mocked(assistantApi.messages).mockImplementationOnce(() => new Promise((resolve) => {
      releaseInitialMessages = resolve;
    })).mockResolvedValueOnce([{
      id: "recovered-reply", sessionId: "main", role: "assistant", content: "已恢复终态回复",
      createdAt: "2026-01-01T00:00:00Z", metadata: { agentRunId: "cold-run" },
    }]);
    const element = await render(true);
    expect(assistantApi.messages).toHaveBeenCalledExactlyOnceWith("main");
    try {
      await act(async () => releaseReceipt({
        id: "cold-run", sessionId: "main", status: "completed", providerKind: "dsh", executionOwner: "external",
      } as never));
      await waitForAssistantText(element, "已恢复终态回复");
      expect(assistantApi.messages).toHaveBeenCalledTimes(2);
      expect(assistantApi.findRequest).toHaveBeenCalledTimes(hasJournal ? 1 : 0);
    } finally {
      await act(async () => releaseInitialMessages([]));
    }
    expect(element.textContent).toContain("已恢复终态回复");
  });

  it.each(["android", "ios", "darwin"])(
    "offers personal data export only when %s supports saving files",
    async (platform) => {
      useAppStore.getState().setHost({
        serverUrl: "https://fixture.example",
        configurationSource: "runtime",
        managedByEnvironment: false,
        app: {
          name: "Soha",
          version: "fixture",
          platform,
          arch: "arm64",
          logDirectory: "",
          updateSupported: false,
        },
      });
      vi.mocked(assistantApi.environment).mockResolvedValueOnce({
        assistantId: "assistant-1",
        state: "sleeping",
        version: 3,
        dataInitialized: true,
      });
      const element = await render(true);
      await click("我的");
      await waitForAssistantText(element, "导出持久文件");
      const button = element.querySelector<HTMLButtonElement>(
        'button[aria-label="导出持久文件"]',
      );
      expect(button?.disabled).toBe(platform !== "darwin");
      if (platform !== "darwin") {
        expect(element.textContent).toContain("当前设备暂不支持文件导出，请使用桌面端或 Web。");
        await click("导出持久文件");
        expect(assistantApi.exportEnvironmentData).not.toHaveBeenCalled();
      } else {
        await click("导出持久文件");
        expect(assistantApi.exportEnvironmentData).toHaveBeenCalledExactlyOnceWith(
          { assistantId: "assistant-1", environmentVersion: 3 },
          expect.any(AbortSignal),
        );
      }
    },
  );
  it("requires approval before reading personal sessions or ensuring the assistant", async () => {
    vi.mocked(assistantApi.access).mockResolvedValueOnce({
      userId: "user-1",
      status: "not_requested",
      version: 0,
    });
    vi.mocked(assistantApi.requestAccess).mockResolvedValueOnce({
      userId: "user-1",
      status: "pending",
      version: 1,
    });
    const element = await render(true);
    expect(element.textContent).toContain("Heya · 嘿呀");
    expect(assistantApi.ensure).not.toHaveBeenCalled();
    expect(assistantApi.sessions).not.toHaveBeenCalled();
    expect(assistantApi.environment).not.toHaveBeenCalled();
    vi.mocked(assistantApi.access).mockResolvedValueOnce({
      userId: "user-1",
      status: "pending",
      version: 1,
    });
    await click("申请开通");
    expect(assistantApi.requestAccess).toHaveBeenCalledOnce();
    await waitForAssistantText(element, "等待管理员批准");
  });
  it("does not read an ordinary session passed through a Heya URL", async () => {
    const element = await render(true, [], "/?session=ordinary-chat");
    expect(element.textContent).toContain("这个会话不属于 Heya");
    expect(assistantApi.messages).not.toHaveBeenCalled();
  });
  it("does not let an old send refresh a newly selected service with the same user ID", async () => {
    const app = {
      name: "Soha",
      version: "fixture",
      platform: "darwin",
      arch: "arm64",
      logDirectory: "",
      updateSupported: false,
    };
    const host = {
      serverUrl: "https://first.example",
      configurationSource: "runtime" as const,
      managedByEnvironment: false,
      app,
    };
    useAppStore.getState().setHost(host);
    let finish!: () => void;
    vi.mocked(streamAssistant).mockImplementationOnce(
      () =>
        new Promise<void>((resolve) => {
          finish = resolve;
        }),
    );
    const element = await render(true);
    const input = element.querySelector<HTMLTextAreaElement>(
      'textarea[aria-label="给助手发消息"]',
    )!;
    await act(async () => {
      Object.getOwnPropertyDescriptor(
        HTMLTextAreaElement.prototype,
        "value",
      )?.set?.call(input, "old-service-task");
      input.dispatchEvent(new Event("input", { bubbles: true }));
    });
    await click("发送");
    const signal = vi.mocked(streamAssistant).mock.calls[0][2];
    const bootstrap = useAppStore.getState().bootstrap!;
    await act(async () => {
      useAppStore
        .getState()
        .setHost({ ...host, serverUrl: "https://second.example" });
      useAppStore.getState().setBootstrap(bootstrap);
      await new Promise((resolve) => setTimeout(resolve, 20));
    });
    expect(signal.aborted).toBe(true);
    // The new service must finish its access check before measuring stale-send refreshes.
    for (let attempt = 0, stable = 0; attempt < 40 && stable < 2; attempt++) {
      await act(async () => {
        await new Promise((resolve) => setTimeout(resolve, 10));
      });
      stable = client!.isFetching() ? 0 : stable + 1;
    }
    const calls = vi.mocked(assistantApi.tasks).mock.calls.length;
    await act(async () => {
      finish();
      await new Promise((resolve) => setTimeout(resolve, 20));
    });
    expect(assistantApi.tasks).toHaveBeenCalledTimes(calls);
    expect(element.textContent).not.toContain("old-service-task");
    expect(
      element.querySelector<HTMLTextAreaElement>(
        'textarea[aria-label="给助手发消息"]',
      )?.value,
    ).toBe("");
    await act(async () => {
      useAppStore.setState({ host: null });
    });
  });
  it("recovers a lost creation response after reload by reads only and keeps absence unconfirmed", async () => {
    vi.mocked(assistantApi.events).mockResolvedValue({
      items: [], nextSequence: 0, hasMore: false, resyncRequired: false,
    });
    const owner = JSON.stringify([
      useAppStore.getState().host?.serverUrl || "",
      "user-1",
    ]);
    savePendingRequest(owner, "main", "lost-response");
    const element = await render(true);
    await waitForAssistantText(element, "任务提交结果未确认");
    expect(readPendingRequests(owner, "main")).toEqual(["lost-response"]);
    expect(assistantApi.findRequest).toHaveBeenCalledWith(
      "main",
      "lost-response",
    );
    expect(streamAssistant).not.toHaveBeenCalled();
    const timestamp = new Date().toISOString();
    vi.mocked(assistantApi.findRequest).mockResolvedValueOnce({
      id: "original",
      sessionId: "main",
      providerId: "internal",
      providerKind: "native",
      capabilityId: "general",
      createdBy: "user-1",
      status: "completed",
      timeoutSeconds: 600,
      queuedAt: timestamp,
      createdAt: timestamp,
      updatedAt: timestamp,
    });
    await click("重新读取");
    expect(readPendingRequests(owner, "main")).toEqual([]);
    expect(element.textContent).not.toContain("任务提交结果未确认");
    expect(assistantApi.events).toHaveBeenCalledWith("original", 0, expect.any(AbortSignal));
    expect(streamAssistant).not.toHaveBeenCalled();
    expect(assistantApi.resume).not.toHaveBeenCalled();
  });
  it("keeps a pasted image ordinary and displays the persisted AI reaction on its user message", async () => {
    const original = vi.mocked(assistantApi.messages).getMockImplementation()!;
    const image = {
      id: "image",
      name: "diagram.png",
      dataUrl: "data:image/png;base64,aGVsbG8=",
    };
    const prepare = vi
      .spyOn(imageHelpers, "prepareChatImage")
      .mockResolvedValue(image);
    vi.mocked(assistantApi.messages).mockResolvedValue([
      {
        id: "user",
        sessionId: "main",
        role: "user",
        content: "hi",
        createdAt: "",
        metadata: { images: [image] },
      },
      {
        id: "reply",
        sessionId: "main",
        role: "assistant",
        content: "Hello",
        createdAt: "",
        metadata: { requestMessageId: "user", assistantReaction: "👋" },
      },
    ]);
    try {
      await render(true);
      await waitForAssistantText(node!, "Hello");
      expect(
        node!.querySelector('[aria-label="助手回应 👋"]')?.closest(".is-user"),
      ).toBeTruthy();
      const input = node!.querySelector<HTMLTextAreaElement>("textarea")!;
      await act(async () => {
        Object.getOwnPropertyDescriptor(
          HTMLTextAreaElement.prototype,
          "value",
        )!.set!.call(input, "分析这张图片");
        input.dispatchEvent(new Event("input", { bubbles: true }));
      });
      await act(async () => {
        const event = new Event("paste", { bubbles: true });
        Object.defineProperty(event, "clipboardData", {
          value: {
            files: [
              new File(["fixture"], "diagram.png", { type: "image/png" }),
            ],
          },
        });
        input.dispatchEvent(event);
        await new Promise((resolve) => setTimeout(resolve, 20));
      });
      expect(prepare).toHaveBeenCalledOnce();
      expect(input.value).toBe("分析这张图片");
      expect(node!.textContent).not.toContain("形象参考图");
      await click("发送");
      const request = vi.mocked(streamAssistant).mock.calls.at(-1)![1];
      expect(request.assistantTask).toBeUndefined();
      expect(request.contextSelection?.images).toEqual([image]);
    } finally {
      prepare.mockRestore();
      vi.mocked(assistantApi.messages).mockImplementation(original);
    }
  });
  it("prefills appearance in chat, preserves the original draft and sends a one-turn task", async () => {
    await render(true);
    await waitForAssistantText(node!, "欢迎回来");
    const enter = async (value: string) =>
      act(async () => {
        const input = node!.querySelector<HTMLTextAreaElement>("textarea")!;
        Object.getOwnPropertyDescriptor(
          HTMLTextAreaElement.prototype,
          "value",
        )!.set!.call(input, value);
        input.dispatchEvent(new Event("input", { bubbles: true }));
      });
    await enter("已有草稿");
    const customize = async () => {
      await click("我的");
      await act(async () => {
        node!
          .querySelector<HTMLButtonElement>('[aria-label="编辑助手资料"]')!
          .click();
        await new Promise((resolve) => setTimeout(resolve, 20));
      });
      await act(async () => {
        [...document.querySelectorAll<HTMLElement>(".ant-dropdown-menu-item")]
          .find((item) => item.textContent?.includes("更改形象"))!
          .click();
        await new Promise((resolve) => setTimeout(resolve, 20));
      });
    };
    await customize();
    expect(node!.querySelector<HTMLTextAreaElement>("textarea")!.value).toBe(
      "把虚拟形象改成 ",
    );
    expect(node!.textContent).toContain("返回原草稿");
    await click("返回原草稿");
    expect(node!.querySelector<HTMLTextAreaElement>("textarea")!.value).toBe(
      "已有草稿",
    );
    await customize();
    await enter("把虚拟形象改成白色机器人");
    await click("发送");
    expect(streamAssistant).toHaveBeenCalledWith(
      "main",
      expect.objectContaining({
        content: "把虚拟形象改成白色机器人",
        assistantTask: { kind: "avatar" },
      }),
      expect.any(AbortSignal),
      expect.any(Function),
    );
  });
  it("requires the full current name and version, and cancellation never deletes data", async () => {
    const receipt = {
      assistantId: "assistant-1",
      state: "sleeping" as const,
      version: 3,
      dataInitialized: true,
    };
    vi.mocked(assistantApi.environment).mockResolvedValueOnce(receipt);
    await render(true);
    await click("我的");
    await click("删除持久数据");
    const enter = async (value: string) =>
      act(async () => {
        const input = document.body.querySelector<HTMLInputElement>(
          'input[aria-label="确认删除数据的助手全名"]',
        )!;
        Object.getOwnPropertyDescriptor(
          HTMLInputElement.prototype,
          "value",
        )!.set!.call(input, value);
        input.dispatchEvent(new Event("input", { bubbles: true }));
        await new Promise((resolve) => setTimeout(resolve, 20));
      });
    const modalButton = (text: string) =>
      [
        ...document.body.querySelectorAll<HTMLButtonElement>(
          ".ant-modal button",
        ),
      ].find((b) => b.textContent?.replace(/\s/g, "") === text)!;
    await enter("小");
    expect(modalButton("确认删除数据").disabled).toBe(true);
    await act(async () => {
      modalButton("取消").click();
      await new Promise((resolve) => setTimeout(resolve, 20));
    });
    expect(assistantApi.deleteEnvironmentData).not.toHaveBeenCalled();
    await click("删除持久数据");
    await enter("小苏");
    expect(modalButton("确认删除数据").disabled).toBe(false);
    await act(async () => {
      client!.setQueryData(
        [
          "assistant-environment",
          selectAssistantOwner(useAppStore.getState()),
          "assistant-1",
        ],
        {
          ...receipt,
          version: 4,
        },
      );
      await new Promise((resolve) => setTimeout(resolve, 20));
    });
    expect(modalButton("确认删除数据").disabled).toBe(true);
    await act(async () => {
      modalButton("取消").click();
      await new Promise((resolve) => setTimeout(resolve, 20));
    });
    await click("删除持久数据");
    await enter("小苏");
    const deleted = { ...receipt, state: "deleted" as const, version: 5 };
    vi.mocked(assistantApi.deleteEnvironmentData).mockResolvedValueOnce(
      deleted,
    );
    vi.mocked(assistantApi.environment).mockResolvedValueOnce(deleted);
    await act(async () => {
      modalButton("确认删除数据").click();
      await new Promise((resolve) => setTimeout(resolve, 20));
    });
    expect(
      vi
        .mocked(assistantApi.deleteEnvironmentData)
        .mock.calls.map(([input]) => input),
    ).toEqual([
      {
        assistantId: "assistant-1",
        environmentVersion: 4,
        confirmationName: "小苏",
      },
    ]);
    await waitForAssistantText(node!, "持久数据已删除");
  });

  it("requires reconciliation before an explicit retry of unknown data deletion", async () => {
    const receipt = {
      assistantId: "assistant-1",
      state: "deletion_unknown" as const,
      version: 3,
      dataInitialized: true,
    };
    vi.mocked(assistantApi.environment)
      .mockResolvedValueOnce(receipt)
      .mockResolvedValueOnce(receipt);
    vi.mocked(assistantApi.changeEnvironment).mockResolvedValueOnce(receipt);
    const element = await render(true);
    await click("我的");
    await waitForAssistantText(element, "数据删除结果未确认");
    const button = [
      ...element.querySelectorAll<HTMLButtonElement>("button"),
    ].find((b) => b.textContent === "删除持久数据")!;
    expect(button.disabled).toBe(true);
    await click("核对环境");
    expect(button.disabled).toBe(false);
    expect(assistantApi.deleteEnvironmentData).not.toHaveBeenCalled();
    expect(assistantApi.changeEnvironment).toHaveBeenCalledExactlyOnceWith(
      "assistant-1",
      { action: "reconcile" },
    );
  });
  it("reconciles an unknown lease once and refreshes after a lost action receipt", async () => {
    const receipt = {
      assistantId: "assistant-1",
      state: "unknown" as const,
      version: 3,
      dataInitialized: true,
      templateId: "personal",
    };
    vi.mocked(assistantApi.environment)
      .mockResolvedValueOnce(receipt)
      .mockResolvedValueOnce(receipt);
    vi.mocked(assistantApi.changeEnvironment).mockRejectedValueOnce(
      new Error("lost receipt"),
    );
    const element = await render(true);
    await click("我的");
    await waitForAssistantText(element, "个人工作空间：状态未确认");
    expect(
      [...element.querySelectorAll("button")].some(
        (button) => button.textContent === "唤醒环境",
      ),
    ).toBe(false);
    await click("核对环境");
    for (
      let attempt = 0;
      attempt < 30 && vi.mocked(assistantApi.environment).mock.calls.length < 2;
      attempt++
    ) {
      await act(async () => {
        await new Promise((resolve) => setTimeout(resolve, 10));
      });
    }
    expect(assistantApi.changeEnvironment).toHaveBeenCalledExactlyOnceWith(
      "assistant-1",
      { action: "reconcile" },
    );
    expect(assistantApi.environment).toHaveBeenCalledTimes(2);
    expect(streamAssistant).not.toHaveBeenCalled();
  });
  it.each([
    ["ready", "就绪"],
    ["sleeping", "休眠"],
    ["unknown", "状态未确认"],
    ["deleting", "正在删除数据"],
    ["deletion_unknown", "数据删除结果未确认"],
    ["deleted", "持久数据已删除"],
  ] as const)(
    "reads %s environment state without dispatching work",
    async (state, label) => {
      vi.mocked(assistantApi.environment).mockResolvedValueOnce({
        assistantId: "assistant-1",
        state,
        version: 3,
        dataInitialized: true,
        observedAt: "2026-10-08T04:00:00Z",
      });
      const element = await render(true);
      expect(assistantApi.environment).not.toHaveBeenCalled();
      await click("我的");
      await waitForAssistantText(element, `个人工作空间：${label}`);
      expect(assistantApi.environment).toHaveBeenCalledWith("assistant-1");
      expect(streamAssistant).not.toHaveBeenCalled();
    },
  );

  it("identifies a VM template and keeps pending environment actions unavailable while chat stays usable", async () => {
    vi.mocked(assistantApi.environmentTemplates).mockResolvedValueOnce([
      {
        id: "assigned-vm",
        name: "专用环境",
        backend: "vm",
        provider: "pve",
        policyRevision: "sha256:" + "a".repeat(64),
        mode: "restricted-write",
        leaseSeconds: 600,
        quota: {
          diskBytes: 1 << 30,
          memoryBytes: 64 << 20,
          cpuUnits: 250,
          maxProcesses: 16,
          networkEgress: false,
        },
      },
    ]);
    const element = await render(true);
    await click("我的");
    await waitForAssistantText(element, "开通个人环境");
    await selectOption("个人环境模板", "专用环境（VM · PVE）");
    const pending = {
      assistantId: "assistant-1",
      state: "pending" as const,
      backend: "vm" as const,
      provider: "pve" as const,
      version: 1,
      dataInitialized: false,
    };
    vi.mocked(assistantApi.changeEnvironment).mockResolvedValueOnce(pending);
    vi.mocked(assistantApi.environment).mockResolvedValueOnce(pending);
    await click("开通个人环境");
    await waitForAssistantText(element, "个人工作空间：VM 待就绪");
    expect(element.textContent).toContain(
      "就绪前个人环境操作不可用，聊天仍可继续。",
    );
    expect(element.textContent).not.toContain("休眠环境");
    expect(element.textContent).not.toContain("导出持久文件");
    expect(element.textContent).not.toContain("删除持久数据");
    expect(assistantApi.changeEnvironment).toHaveBeenCalledExactlyOnceWith(
      "assistant-1",
      {
        action: "wake",
        templateId: "assigned-vm",
      },
    );
    expect(assistantApi.deleteEnvironmentData).not.toHaveBeenCalled();
    await click("对话");
    expect(
      element.querySelector<HTMLTextAreaElement>(
        'textarea[aria-label="给助手发消息"]',
      )?.disabled,
    ).toBe(false);
    expect(streamAssistant).not.toHaveBeenCalled();
  });

  it("keeps unavailable receipts visible and refreshes only the state", async () => {
    vi.mocked(assistantApi.environment).mockRejectedValueOnce(
      new Error("receipt unavailable"),
    );
    const element = await render(true);
    await click("我的");
    await waitForAssistantText(element, "个人工作空间：读取失败");
    await click("刷新环境状态");
    await waitForAssistantText(element, "个人工作空间：未开通");
    expect(streamAssistant).not.toHaveBeenCalled();
  });
  it("restores model and knowledge preferences from the current server session without inheriting transient memories", async () => {
    vi.mocked(streamAssistant).mockResolvedValue(undefined);
    vi.mocked(assistantApi.sessions).mockResolvedValueOnce([
      {
        id: "main",
        title: "主聊天",
        createdBy: "user-1",
        createdAt: "2026-10-08T00:00:00Z",
        updatedAt: "2026-10-08T00:00:00Z",
        metadata: {
          modelPreferences: { publicModel: "model-A", reasoningEffort: "auto" },
          knowledgeContext: {
            enabled: true,
            knowledgeBaseIds: ["kb-authorized"],
          },
        },
      },
    ]);
    const element = await render(true, [
      "observe.ai.view",
      "ai.knowledge.view",
    ]);
    const input = element.querySelector<HTMLTextAreaElement>(
      'textarea[aria-label="给助手发消息"]',
    )!;
    await act(async () => {
      Object.getOwnPropertyDescriptor(
        HTMLTextAreaElement.prototype,
        "value",
      )?.set?.call(input, "刷新后继续");
      input.dispatchEvent(new Event("input", { bubbles: true }));
    });
    await click("发送");
    expect(vi.mocked(streamAssistant).mock.calls[0][1]).toMatchObject({
      modelPreferences: { publicModel: "model-A", reasoningEffort: "auto" },
      knowledgeContext: { enabled: true, knowledgeBaseIds: ["kb-authorized"] },
      contextSelection: { memoryIds: [] },
    });
  });
  it("keeps model, authorized knowledge and explicit memory selections on the public request", async () => {
    vi.mocked(streamAssistant).mockResolvedValue(undefined);
    vi.mocked(assistantApi.messages).mockResolvedValueOnce([
      {
        id: "m1",
        sessionId: "main",
        role: "assistant",
        content: "欢迎回来",
        createdAt: "2026-10-08T00:00:00Z",
        metadata: {
          contextUsage: {
            measurement: "reported",
            model: "model-A",
            inputTokens: 8000,
            outputTokens: 200,
            contextWindowTokens: 128000,
          },
          contextEnvelope: {
            citations: [
              {
                id: "citation-1",
                documentTitle: "已使用的运行手册",
                documentVersionId: "version-2",
                uri: "soha://knowledge/document/doc-1",
              },
            ],
            budgetUsage: { evidenceTokens: 32 },
            principal: { userId: "private-principal-must-not-render" },
          },
        },
      },
    ]);
    const element = await render(true, [
      "observe.ai.view",
      "ai.knowledge.view",
      "ai.memory.view",
    ]);
    await click("实际背景与来源");
    expect(document.body.textContent).toContain("已使用的运行手册");
    expect(document.body.textContent).toContain("版本 version-2");
    expect(document.body.textContent).toContain("证据用量估算 32 tokens");
    expect(document.body.textContent).not.toContain(
      "private-principal-must-not-render",
    );
    await click("实际背景与来源");
    const contextTrigger = element.querySelector<HTMLButtonElement>(
      '[aria-label="上下文用量与背景来源"]',
    )!;
    expect(contextTrigger.closest(".app-assistant-composer-row")).toBeTruthy();
    expect(contextTrigger.title).toBe("上下文 8K / 128K");
    expect(contextTrigger.textContent).toBe("");
    await click("上下文用量与背景来源");
    expect(document.body.textContent).toContain("上下文 8K / 128K");
    expect(document.body.textContent).toContain("模型上游回报");
    expect(document.body.textContent).not.toContain("完整模型输入用量未知");
    await click("上下文用量与背景来源");
    await click("模型与思考强度");
    await selectOption("模型", "model-A");
    await click("模型与思考强度");
    await click("添加内容");
    await click("添加背景");
    await selectOption("知识库", "运行手册");
    await act(async () => {
      [...document.body.querySelectorAll<HTMLButtonElement>("button")]
        .find((button) => button.textContent?.replace(/\s/g, "") === "完成")!
        .click();
      await new Promise((resolve) => setTimeout(resolve, 20));
    });
    await click("个人记忆");
    let memoryLabel: HTMLLabelElement | undefined;
    for (let attempt = 0; attempt < 20 && !memoryLabel; attempt++) {
      memoryLabel = [
        ...document.body.querySelectorAll<HTMLLabelElement>(
          "label.ant-checkbox-wrapper",
        ),
      ].find((item) => item.textContent === "发布前检查");
      if (!memoryLabel)
        await act(async () => {
          await new Promise((resolve) => setTimeout(resolve, 10));
        });
    }
    expect(memoryLabel).toBeTruthy();
    await act(async () => {
      memoryLabel!.click();
    });
    await act(async () => {
      [...document.body.querySelectorAll<HTMLButtonElement>("button")]
        .find((button) => button.textContent?.replace(/\s/g, "") === "完成")!
        .click();
      await new Promise((resolve) => setTimeout(resolve, 20));
    });
    const input = element.querySelector<HTMLTextAreaElement>(
      'textarea[aria-label="给助手发消息"]',
    )!;
    await act(async () => {
      Object.getOwnPropertyDescriptor(
        HTMLTextAreaElement.prototype,
        "value",
      )?.set?.call(input, "依据背景回答");
      input.dispatchEvent(new Event("input", { bubbles: true }));
    });
    await click("发送");
    expect(vi.mocked(streamAssistant).mock.calls[0][1]).toMatchObject({
      modelPreferences: { publicModel: "model-A", reasoningEffort: "auto" },
      knowledgeContext: { enabled: true, knowledgeBaseIds: ["kb-authorized"] },
      contextSelection: { memoryIds: ["memory-1"] },
    });
    expect(assistantApi.saveMemory).not.toHaveBeenCalled();
  });
  it("chooses thinking effort inside the model menu and resets it on a model change", async () => {
    vi.mocked(assistantApi.catalog).mockResolvedValueOnce({
      adapters: [],
      dataSources: [],
      analysisProfiles: [],
      defaultPublicModel: "model-A",
      modelOptions: [
        { publicModel: "model-A", reasoningEfforts: ["low", "medium", "high"] },
        { publicModel: "model-B", reasoningEfforts: [] },
      ],
    });
    vi.mocked(streamAssistant).mockResolvedValue(undefined);
    const element = await render(true, ["observe.ai.view"]);
    await click("模型与思考强度");
    await selectOption("模型", "model-A");
    const chooseHigh = async () =>
      act(async () => {
        [
          ...document.body.querySelectorAll<HTMLLabelElement>(
            ".app-assistant-model-menu label.ant-segmented-item",
          ),
        ]
          .find((item) => item.textContent === "深度")!
          .querySelector("input")!
          .click();
      });
    await chooseHigh();
    expect(
      element.querySelector(".app-assistant-model-effort")?.textContent,
    ).toBe("深度");
    await selectOption("模型", "model-B");
    const automatic = document.body.querySelector<HTMLInputElement>(
      '.app-assistant-model-menu input[type="radio"]',
    )!;
    expect(automatic.checked).toBe(true);
    expect(automatic.disabled).toBe(true);
    expect(
      element.querySelector(".app-assistant-model-effort")?.textContent,
    ).toBe("自动");
    await selectOption("模型", "model-A");
    await chooseHigh();
    await click("模型与思考强度");
    const input = element.querySelector<HTMLTextAreaElement>(
      'textarea[aria-label="给助手发消息"]',
    )!;
    await act(async () => {
      Object.getOwnPropertyDescriptor(
        HTMLTextAreaElement.prototype,
        "value",
      )?.set?.call(input, "深入解释一下");
      input.dispatchEvent(new Event("input", { bubbles: true }));
    });
    await click("发送");
    expect(vi.mocked(streamAssistant).mock.calls[0][1]).toMatchObject({
      modelPreferences: { publicModel: "model-A", reasoningEffort: "high" },
    });
  });
  it("saves only an explicit confirmed private memory with the persisted message source", async () => {
    const element = await render(true, ["ai.memory.view", "ai.memory.update"]);
    await click("保存为个人记忆");
    await act(async () => {
      await new Promise((resolve) => setTimeout(resolve, 30));
    });
    expect(assistantApi.saveMemory).not.toHaveBeenCalled();
    const save = [
      ...document.body.querySelectorAll<HTMLButtonElement>("button"),
    ].find((button) => button.textContent === "确认保存个人记忆")!;
    expect(save.disabled).toBe(false);
    await act(async () => {
      save.click();
      await new Promise((resolve) => setTimeout(resolve, 30));
    });
    expect(assistantApi.saveMemory).toHaveBeenCalledTimes(1);
    expect(vi.mocked(assistantApi.saveMemory).mock.calls[0][0]).toMatchObject({
      policyId: "personal",
      policyVersion: "1",
      record: {
        ownerType: "user",
        ownerId: "user-1",
        fact: "欢迎回来",
        sourceType: "explicit_user",
        sourceRefs: ["soha://session/main/message/m1"],
        status: "active",
      },
    });
    expect(element.textContent).toContain("欢迎回来");
  });
  it("submits a one-turn combination with actual sources and keeps the following message ordinary", async () => {
    vi.mocked(assistantApi.events).mockResolvedValue({
      items: [], nextSequence: 0, hasMore: false, resyncRequired: false,
    });
    const terminal = {id: "analysis-finished", sessionId: "main", providerKind: "native", status: "completed"} as never;
    vi.mocked(assistantApi.tasks).mockResolvedValueOnce([]).mockResolvedValueOnce([terminal]);
    vi.mocked(assistantApi.findRequest).mockResolvedValueOnce(terminal);
    vi.mocked(streamAssistant).mockResolvedValue(undefined);
    const element = await render(true, [
      "observe.ai.view",
      "observe.ai.root-cause.run",
      "observe.monitoring.view",
      "ai.gateway.invoke",
    ]);
    await click("添加内容");
    await click("专业分析任务");
    for (const label of ["根因分析", "性能分析", "链路分析", "巡检复盘"]) {
      const checkbox = [
        ...document.body.querySelectorAll<HTMLLabelElement>(
          "label.ant-checkbox-wrapper",
        ),
      ].find((item) => item.textContent === label)!;
      expect(checkbox).toBeTruthy();
      await act(async () => {
        checkbox.click();
      });
    }
    await selectOption("根因分析模板", "发布根因模板");
    await selectOption("指标数据源", "Prometheus");
    await selectOption("性能指标", "P95 延迟");
    await selectOption("链路数据源", "SkyWalking");
    await selectOption("巡检执行记录", "真实巡检记录");
    for (const [label, value] of [
      ["Trace ID", "trace-selected"],
      ["分析目标", "调查发布失败"],
    ]) {
      const input = document.body.querySelector<
        HTMLInputElement | HTMLTextAreaElement
      >(`[aria-label="${label}"]`)!;
      await act(async () => {
        Object.getOwnPropertyDescriptor(
          input.tagName === "TEXTAREA"
            ? HTMLTextAreaElement.prototype
            : HTMLInputElement.prototype,
          "value",
        )?.set?.call(input, value);
        input.dispatchEvent(new Event("input", { bubbles: true }));
      });
    }
    const start = [
      ...document.body.querySelectorAll<HTMLButtonElement>("button"),
    ].find((button) => button.textContent?.replace(/ /g, "") === "开始分析")!;
    await act(async () => {
      start.click();
    });
    await vi.waitFor(() => expect(streamAssistant).toHaveBeenCalledTimes(1), {
      interval: 5,
      timeout: 1000,
    });
    expect(vi.mocked(streamAssistant).mock.calls[0][1]).toMatchObject({
      content: "调查发布失败",
      agentProviderId: "dsh",
      requestId: expect.any(String),
      taskIntent: {
        capabilities: [
          "root_cause",
          "performance",
          "trace",
          "inspection_review",
        ],
        rootCauseProfileId: "root-profile",
        performanceDataSourceId: "metrics-source",
        metricKey: "latency_p95",
        traceDataSourceId: "trace-source",
        traceId: "trace-selected",
        minDurationMs: 0,
        inspectionRunIds: ["inspection-done"],
      },
    });
    const input = element.querySelector<HTMLTextAreaElement>(
      'textarea[aria-label="给助手发消息"]',
    )!;
    await act(async () => {
      Object.getOwnPropertyDescriptor(
        HTMLTextAreaElement.prototype,
        "value",
      )?.set?.call(input, "继续普通对话");
      input.dispatchEvent(new Event("input", { bubbles: true }));
    });
    await click("发送");
    await vi.waitFor(() => expect(streamAssistant).toHaveBeenCalledTimes(2), {
      interval: 5,
      timeout: 1000,
    });
    expect(vi.mocked(streamAssistant).mock.calls[1][1].taskIntent).toEqual({
      capabilities: [],
    });
    expect(assistantApi.metrics).toHaveBeenCalledWith("metrics-source");
    expect(assistantApi.events).toHaveBeenCalledWith("analysis-finished", 0, expect.any(AbortSignal));
  }, 20_000);
  it("retains the draft after a failed send and never replays the POST", async () => {
    vi.mocked(streamAssistant).mockRejectedValueOnce(new Error("Send failed"));
    const element = await render(true);
    for (
      let attempt = 0;
      attempt < 20 && !element.textContent?.includes("欢迎回来");
      attempt++
    ) {
      await act(async () => {
        await new Promise((resolve) => setTimeout(resolve, 10));
      });
    }
    const input = element.querySelector<HTMLTextAreaElement>("textarea")!;
    await act(async () => {
      Object.getOwnPropertyDescriptor(
        HTMLTextAreaElement.prototype,
        "value",
      )?.set?.call(input, "保留这条消息");
      input.dispatchEvent(new Event("input", { bubbles: true }));
    });
    await click("发送");
    expect(input.value).toBe("保留这条消息");
    expect(streamAssistant).toHaveBeenCalledTimes(1);
  });
  it("does not request personal data without chat permission", async () => {
    const element = await render(false);
    expect(element.textContent).toContain("没有 AI 对话使用权限");
    expect(assistantApi.ensure).not.toHaveBeenCalled();
    expect(assistantApi.tasks).not.toHaveBeenCalled();
    expect(assistantApi.artifacts).not.toHaveBeenCalled();
  });
  it("recovers dsh events and resumes the same run without sending a new message", async () => {
    const timestamp = "2026-10-08T00:00:00Z";
    const run = {
      id: "native-run",
      sessionId: "main",
      providerId: "dsh",
      providerKind: "dsh",
      executionOwner: "external" as const,
      capabilityId: "general",
      createdBy: "user-1",
      status: "running",
      phase: "paused",
      stopReason: "waiting_input",
      timeoutSeconds: 600,
      queuedAt: timestamp,
      createdAt: timestamp,
      updatedAt: timestamp,
      output: { pendingQuestion: "请补充发布窗口。" },
    };
    vi.mocked(assistantApi.tasks).mockResolvedValueOnce([run]);
    vi.mocked(assistantApi.events).mockImplementation(async (_, after) => ({
      items:
        after === 0
          ? [
              {
                id: "native-e1",
                sessionId: "main",
                runId: run.id,
                sequence: 1,
                createdAt: timestamp,
                type: "message.delta",
                messageId: "native-reply",
                role: "assistant",
                contentDelta: "实际持久进度",
              },
            ]
          : [],
      nextSequence: 1,
      hasMore: false,
      resyncRequired: false,
    }));
    vi.mocked(assistantApi.resume).mockResolvedValueOnce({
      ...run,
      phase: "waiting_task",
      stopReason: "",
    });
    vi.mocked(assistantApi.tasks).mockResolvedValueOnce([
      { ...run, phase: "waiting_task", stopReason: "" },
    ]);
    const element = await render(true);
    await click("任务");
    await act(async () => {
      await new Promise((resolve) => setTimeout(resolve, 30));
    });
    expect(element.textContent).toContain("实际持久进度");
    expect(assistantApi.events).toHaveBeenCalledWith(
      "native-run",
      1,
      expect.any(AbortSignal),
    );
    const input = element.querySelector<HTMLTextAreaElement>(
      'textarea[aria-label="任务 native-run 的补充信息"]',
    )!;
    await act(async () => {
      Object.getOwnPropertyDescriptor(
        HTMLTextAreaElement.prototype,
        "value",
      )?.set?.call(input, "今晚 22:00");
      input.dispatchEvent(new Event("input", { bubbles: true }));
    });
    await click("补充并继续");
    expect(assistantApi.resume).toHaveBeenCalledTimes(1);
    expect(assistantApi.resume).toHaveBeenCalledWith("native-run", {
      input: "今晚 22:00",
    });
    expect(element.textContent).toContain("等待领域执行与验收");
    expect(streamAssistant).not.toHaveBeenCalled();
  });
  it("shows dsh approvals and keeps an acknowledged cancellation pending", async () => {
    const timestamp = "2026-10-08T00:00:00Z";
    const run = {
      id: "native-approval-run",
      sessionId: "side",
      providerId: "dsh",
      providerKind: "dsh",
      executionOwner: "external" as const,
      capabilityId: "general",
      createdBy: "user-1",
      status: "running",
      phase: "waiting_approval",
      timeoutSeconds: 600,
      queuedAt: timestamp,
      createdAt: timestamp,
      updatedAt: timestamp,
      output: { approvalRequestIds: ["approval-native"] },
    };
    vi.mocked(assistantApi.tasks).mockResolvedValueOnce([run]);
    vi.mocked(assistantApi.events).mockResolvedValue({
      items: [],
      nextSequence: 0,
      hasMore: false,
      resyncRequired: false,
    });
    vi.mocked(assistantApi.approvals).mockResolvedValueOnce({
      id: "approval-native",
      toolName: "docker.projects.deploy.trigger",
      toolInput: { projectId: "frozen-project" },
      status: "pending",
      actorType: "user",
      actorId: "user-1",
      riskLevel: "high",
      strategy: "manual",
      requiresApproval: true,
      summary: "冻结参数",
      createdAt: timestamp,
      updatedAt: timestamp,
    });
    vi.mocked(assistantApi.cancel).mockResolvedValueOnce({
      ...run,
      phase: "cancelling",
    });
    vi.mocked(assistantApi.tasks).mockResolvedValueOnce([
      { ...run, phase: "cancelling" },
    ]);
    const element = await render(true, ["ai.gateway.approvals.view"]);
    await click("任务");
    await act(async () => {
      await new Promise((resolve) => setTimeout(resolve, 30));
    });
    expect(element.textContent).toContain("frozen-project");
    expect(element.textContent).toContain("审批结果会继续推进原任务");
    expect(assistantApi.approvals).toHaveBeenCalledWith("approval-native");
    expect(
      [...element.querySelectorAll("button")].some(
        (button) => button.textContent === "批准",
      ),
    ).toBe(false);
    await click("取消任务");
    expect(document.body.textContent).toContain("等待执行端确认");
    expect(element.textContent).toContain("执行中");
    expect(assistantApi.decide).not.toHaveBeenCalled();
  });
  it("shares the server identity, surfaces side-chat tasks and opens persisted results", async () => {
    const element = await render(true);
    expect(element.textContent).toContain("小苏");
    for (
      let attempt = 0;
      attempt < 20 && !element.textContent?.includes("欢迎回来");
      attempt++
    ) {
      await act(async () => {
        await new Promise((resolve) => setTimeout(resolve, 10));
      });
    }
    expect(element.textContent).toContain("欢迎回来");
    await click("任务");
    expect(element.textContent).toContain("整理发布报告");
    await click("成果");
    for (
      let attempt = 0;
      attempt < 20 && !element.textContent?.includes("旁聊直接生成的报告");
      attempt++
    ) {
      await act(async () => {
        await new Promise((resolve) => setTimeout(resolve, 10));
      });
    }
    expect(element.textContent).toContain("旁聊直接生成的报告");
    await click("查看成果");
    expect(document.body.textContent).toContain("报告正文");
    expect(assistantApi.tasks).toHaveBeenCalled();
    expect(assistantApi.cancel).not.toHaveBeenCalled();
  });
});


it("opens ordinary Chat without Heya or environment and recovers the same durable task", async () => {
  vi.mocked(assistantApi.chatTasks).mockResolvedValueOnce([{id: "same-run", sessionId: "chat-main", providerKind: "dsh", executionOwner: "external", status: "running"}] as never);
  vi.mocked(assistantApi.events).mockResolvedValue({items: [], nextSequence: 0, hasMore: false, resyncRequired: false});
  await render(true, [], "/chat", true);
  expect(assistantApi.ensure).not.toHaveBeenCalled();
  expect(assistantApi.environment).not.toHaveBeenCalled();
  expect(assistantApi.chatMain).toHaveBeenCalledTimes(1);
  expect(streamAssistant).not.toHaveBeenCalled();
  expect(document.querySelector<HTMLTextAreaElement>('textarea[aria-label="给助手发消息"]')?.disabled).toBe(true);
});

it("aborts reception immediately and keeps ordinary composer locked until durable cancellation ends", async () => {
  vi.mocked(assistantApi.chatTasks).mockResolvedValue([{id: "stop-run", sessionId: "chat-main", providerKind: "dsh", executionOwner: "external", status: "running"}] as never);
  vi.mocked(assistantApi.events).mockResolvedValue({items: [], nextSequence: 0, hasMore: false, resyncRequired: false});
  vi.mocked(assistantApi.cancel).mockRejectedValueOnce(new Error("offline"));
  await render(true, [], "/chat", true);
  await click("停止接收");
  expect(vi.mocked(assistantApi.cancel).mock.calls[0][0]).toBe("stop-run");
  expect(document.body.textContent).toContain("取消处理中");
  expect(document.querySelector<HTMLTextAreaElement>('textarea[aria-label="给助手发消息"]')?.disabled).toBe(true);
  expect(streamAssistant).not.toHaveBeenCalled();
});


it("shows tombstone propagation without deleted facts and keeps Chat memory explicit", async () => {
  vi.mocked(assistantApi.chatTasks).mockResolvedValue([]);
  vi.mocked(assistantApi.memories).mockResolvedValueOnce([{id: "deleted-memory", ownerType: "user", ownerId: "user-1", fact: "PRIVATE DELETED FACT", status: "deleted", syncStatus: "delete_pending", sourceType: "explicit_user", sourceRefs: []}] as never);
  await render(true, ["ai.memory.view", "ai.memory.update"], "/chat", true);
  await click("添加内容");
  await click("个人记忆");
  expect(document.body.textContent).toContain("已禁用，删除传播中");
  expect(document.body.textContent).not.toContain("PRIVATE DELETED FACT");
  expect(document.querySelector('[aria-label="Heya 自动记忆"]')).toBeNull();
  const toggle = document.querySelector<HTMLButtonElement>('[aria-label="允许读取记忆"]');
  vi.mocked(assistantApi.saveMemoryPolicy).mockResolvedValueOnce({id: "personal", ownerId:"user-1", mode:"chat", enabled:true, readEnabled:true, writeEnabled:false, explicitWriteOnly:true} as never);
  await act(async () => toggle?.click());
  expect(assistantApi.saveMemoryPolicy).toHaveBeenCalledWith(expect.objectContaining({mode:"chat",consentMode:"explicit",readEnabled:false,writeEnabled:true}));
});


it("immediately aborts a live stream while durable cancel is still unresolved", async () => {
  vi.mocked(assistantApi.chatTasks).mockResolvedValue([]);
  vi.mocked(assistantApi.findRequest).mockResolvedValueOnce({id: "live-run", sessionId: "chat-main", providerKind: "dsh", executionOwner: "external", status: "running"} as never);
  let signal: AbortSignal | undefined;
  vi.mocked(streamAssistant).mockImplementationOnce(async (_session, _input, streamSignal) => {
    signal = streamSignal;
    await new Promise<void>((_resolve, reject) => streamSignal.addEventListener("abort", () => reject(new Error("aborted")), {once: true}));
  });
  vi.mocked(assistantApi.cancel).mockRejectedValueOnce(new Error("offline"));
  const element = await render(true, [], "/chat", true);
  const input = element.querySelector<HTMLTextAreaElement>('textarea[aria-label="给助手发消息"]')!;
  await act(async () => {
    Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, "value")?.set?.call(input, "hello");
    input.dispatchEvent(new Event("input", {bubbles: true}));
  });
  await click("发送");
  expect(signal?.aborted).toBe(false);
  await click("停止接收");
  expect(signal?.aborted).toBe(true);
  expect(input.disabled).toBe(true);
  expect(vi.mocked(assistantApi.cancel).mock.calls[0][0]).toBe("live-run");
});


it("lets Chat explicitly select an owned Heya fact without changing its scope", async () => {
  vi.mocked(assistantApi.chatTasks).mockResolvedValue([]);
  vi.mocked(assistantApi.memoryPolicies).mockResolvedValueOnce([{id:"heya-policy",version:"v1",ownerId:"user-1",mode:"heya",ownerTypes:["user"],enabled:true,readEnabled:true,writeEnabled:true,explicitWriteOnly:true}] as never);
  vi.mocked(assistantApi.memories).mockResolvedValueOnce([{id:"shared-heya",policyId:"heya-policy",policyVersion:"v1",ownerType:"user",ownerId:"user-1",fact:"来自 Heya 的偏好",expiresAt:"2099-01-01T00:00:00Z",validFrom:"2026-01-01T00:00:00Z",status:"active",sourceType:"explicit_user",sourceRefs:[],syncStatus:"synced"}] as never);
  await render(true, ["ai.memory.view", "ai.memory.update"], "/chat", true);
  await click("添加内容"); await click("个人记忆");
  const checkbox = document.querySelector<HTMLInputElement>('input[type="checkbox"]')!;
  expect(checkbox.checked).toBe(false); expect(checkbox.disabled).toBe(false);
  await act(async () => checkbox.click());
  expect(checkbox.checked).toBe(true);
  expect(document.body.textContent).toContain("共享至本次会话");
  expect(assistantApi.saveMemory).not.toHaveBeenCalled();
  expect(assistantApi.saveMemoryPolicy).not.toHaveBeenCalled();
});


it("allows local explicit facts without source receipts despite disabled external sync, but respects read consent", async () => {
  vi.mocked(assistantApi.chatTasks).mockResolvedValue([]);
  const policy = {id:"chat-local",version:"v1",ownerId:"user-1",mode:"chat",ownerTypes:["user"],enabled:true,readEnabled:true,writeEnabled:true,explicitWriteOnly:true};
  vi.mocked(assistantApi.memoryPolicies).mockResolvedValueOnce([policy] as never);
  vi.mocked(assistantApi.memories).mockResolvedValueOnce([{id:"local-fact",policyId:"chat-local",policyVersion:"v1",ownerType:"user",ownerId:"user-1",fact:"手动事实",status:"active",sourceType:"explicit_user",sourceRefs:[],syncStatus:"disabled",validFrom:"2026-01-01T00:00:00Z",expiresAt:"2099-01-01T00:00:00Z"}] as never);
  await render(true, ["ai.memory.view"], "/chat", true);
  await click("添加内容"); await click("个人记忆");
  const checkbox = document.querySelector<HTMLInputElement>('input[type="checkbox"]')!;
  expect(checkbox.disabled).toBe(false);
  await act(async () => checkbox.click()); expect(checkbox.checked).toBe(true);
  await act(async () => {
    client!.setQueryData(["assistant-memory-policies", "user-1"], [{...policy,readEnabled:false}]);
  });
  await settleQueries();
  expect(checkbox.disabled).toBe(true);
  expect(checkbox.checked).toBe(true);
  await click("清空本次选择");
  expect(checkbox.checked).toBe(false);
  expect(checkbox.disabled).toBe(true);
});


it.each([false, true])("shows durable memory degradation while conversation stays available (ordinary=%s)", async (ordinary) => {
  vi.mocked(assistantApi.chatTasks).mockResolvedValue([]);
  if (!ordinary) vi.mocked(assistantApi.tasks).mockResolvedValueOnce([]);
  vi.mocked(assistantApi.messages).mockResolvedValueOnce([{id:"degraded-reply",sessionId:ordinary ? "chat-main" : "main",role:"assistant",content:"仍可对话",metadata:{contextSnapshot:{truncations:["memory_unavailable"]}}}] as never);
  const element = await render(true, [], ordinary ? "/chat" : "/", ordinary);
  await waitForAssistantText(element, "长期记忆暂不可用，本次对话将继续");
  expect(element.textContent).not.toContain("memory_unavailable");
  expect(element.querySelector<HTMLTextAreaElement>('textarea[aria-label="给助手发消息"]')?.disabled).toBe(false);
  await act(async () => { client!.setQueryData(ordinary ? ["assistant-tasks", selectAssistantOwner(useAppStore.getState()), true, "chat-main"] : ["assistant-tasks", selectAssistantOwner(useAppStore.getState()), false], [{id:"clean-round",sessionId:ordinary ? "chat-main" : "main",status:"completed",providerKind:"dsh",executionOwner:"external",output:{contextSnapshot:{truncations:[]}}}]); });
  await settleQueries();
  expect(element.textContent).not.toContain("长期记忆暂不可用，本次对话将继续");
});

it("shows auto-memory write failure from the live server event without blocking chat", async () => {
  const terminal = {id:"auto-failed",sessionId:"main",providerKind:"dsh",executionOwner:"external",status:"completed",output:{memoryStatus:"degraded"}} as never;
  vi.mocked(assistantApi.tasks).mockResolvedValueOnce([]).mockResolvedValueOnce([terminal]);
  vi.mocked(streamAssistant).mockImplementationOnce(async (_id, _input, _signal, onEvent) => {
    onEvent({id:"warning",sessionId:"main",runId:"auto-failed",type:"agent.status",status:"succeeded",metadata:{memoryStatus:"degraded",memoryWarning:"server detail"}} as never);
  });
  const element = await render(true);
  const input = element.querySelector<HTMLTextAreaElement>('textarea[aria-label="给助手发消息"]')!;
  await act(async () => {
    Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype,"value")?.set?.call(input,"继续聊天");
    input.dispatchEvent(new Event("input",{bubbles:true}));
  });
  await click("发送");
  await waitForAssistantText(element, "长期记忆暂不可用，本次对话将继续");
  expect(element.textContent).not.toContain("server detail");
  expect(input.disabled).toBe(false);
  expect(streamAssistant).toHaveBeenCalledTimes(1);
});


it("restores auto-memory degradation only from the matching current user message", async () => {
  vi.mocked(assistantApi.tasks).mockResolvedValueOnce([{id:"auto-restored",sessionId:"main",providerKind:"dsh",executionOwner:"external",status:"completed",input:{requestMessageId:"current-request"}}] as never);
  vi.mocked(assistantApi.messages).mockResolvedValueOnce([{id:"current-request",sessionId:"main",role:"user",content:"当前请求",metadata:{agentRunId:"auto-restored",memoryStatus:"degraded",memoryWarning:"raw detail"}}] as never);
  const element = await render(true);
  await waitForAssistantText(element, "长期记忆暂不可用，本次对话将继续");
  expect(element.textContent).not.toContain("raw detail");
  expect(element.querySelector<HTMLTextAreaElement>('textarea[aria-label="给助手发消息"]')?.disabled).toBe(false);
  await act(async () => {client!.setQueryData(["assistant-tasks",selectAssistantOwner(useAppStore.getState()),false],[{id:"new-clean",sessionId:"main",status:"completed"}]);});
  await settleQueries();
  expect(element.textContent).not.toContain("长期记忆暂不可用，本次对话将继续");
});


it("treats enabled false with true flags as disabled for switches and cross-mode selection", async () => {
  vi.mocked(assistantApi.chatTasks).mockResolvedValue([]);
  vi.mocked(assistantApi.memoryPolicies).mockResolvedValueOnce([
    {id:"recipient",version:"v1",ownerId:"user-1",mode:"chat",ownerTypes:["user"],enabled:false,readEnabled:true,writeEnabled:true,explicitWriteOnly:true},
    {id:"donor",version:"v1",ownerId:"user-1",mode:"heya",ownerTypes:["user"],enabled:true,readEnabled:true,writeEnabled:true,explicitWriteOnly:true},
  ] as never);
  vi.mocked(assistantApi.memories).mockResolvedValueOnce([{id:"heya-fact",policyId:"donor",policyVersion:"v1",ownerType:"user",ownerId:"user-1",fact:"另一入口事实",status:"active",sourceType:"explicit_user",sourceRefs:[],syncStatus:"disabled",validFrom:"2026-01-01T00:00:00Z",expiresAt:"2099-01-01T00:00:00Z"}] as never);
  await render(true, ["ai.memory.view","ai.memory.update"], "/chat", true);
  await click("添加内容"); await click("个人记忆");
  expect(document.querySelector('[aria-label="允许读取记忆"]')?.getAttribute("aria-checked")).toBe("false");
  expect(document.querySelector('[aria-label="允许写入记忆"]')?.getAttribute("aria-checked")).toBe("false");
  expect(document.querySelector<HTMLInputElement>('input[type="checkbox"]')?.disabled).toBe(true);
});

it("keeps legacy Native checkpoints readable without a resume control", async () => {
  vi.mocked(assistantApi.chatTasks).mockResolvedValue([{id: "legacy-paused", sessionId: "chat-main", providerKind: "native", status: "running", phase: "paused", stopReason: "waiting_input", output: {pendingQuestion: "old checkpoint", executionReadOnly: true, stopReason: "legacy_reconciliation_required"}}] as never);
  vi.mocked(assistantApi.events).mockResolvedValue({items: [], nextSequence: 0, hasMore: false, resyncRequired: false});
  await render(true, [], "/chat", true);
  expect(document.body.textContent).toContain("历史任务只读");
  expect(document.body.textContent).toContain("历史执行已隔离，等待核对");
  expect(document.body.textContent).not.toContain("补充并继续");
  expect(assistantApi.resume).not.toHaveBeenCalled();
  expect(streamAssistant).not.toHaveBeenCalled();
});
it("restores cancellation pending from the legacy journal by reads only", async () => {
  const owner = JSON.stringify([useAppStore.getState().host?.serverUrl || "", "user-1"]);
  const key = `soha.app.native-request.v1:${encodeURIComponent(owner)}/chat-main/lost-stop`;
  localStorage.setItem(key, JSON.stringify({cancelPending: true}));
  vi.mocked(assistantApi.findRequest).mockResolvedValue({id: "stopping-run", sessionId: "chat-main", providerKind: "dsh", executionOwner: "external", status: "running", phase: "cancelling"} as never);
  vi.mocked(assistantApi.chatTasks).mockResolvedValue([]);
  vi.mocked(assistantApi.events).mockResolvedValue({items: [], nextSequence: 0, hasMore: false, resyncRequired: false});
  await render(true, [], "/chat", true);
  await act(async () => { await new Promise(resolve => setTimeout(resolve, 30)); });
  expect(document.body.textContent).toContain("取消处理中");
  expect(document.querySelector<HTMLTextAreaElement>('textarea[aria-label="给助手发消息"]')?.disabled).toBe(true);
  expect(readPendingRequests(owner, "chat-main")).toEqual(["lost-stop"]);
  expect(assistantApi.cancel).not.toHaveBeenCalled();
  expect(streamAssistant).not.toHaveBeenCalled();
  expect(localStorage.getItem(key)).not.toBeNull();
});

it("shows quarantine without changing fact status and preserves local-only selectable records", async () => {
  const base = {ownerType: "user", ownerId: "user-1", status: "active", policyId: "personal", policyVersion: "1", validFrom: "2020-01-01T00:00:00Z", expiresAt: "2099-01-01T00:00:00Z", sourceType: "explicit_user", sourceRefs: ["soha://session/original/message/source"], syncStatus: "disabled"};
  vi.mocked(assistantApi.memories).mockResolvedValueOnce([
    {...base, id: "quarantine", fact: "待核对事实", quarantined: true, quarantineReason: "legacy_scope_unverified"},
    {...base, id: "local-only", fact: "仍可本地使用"},
  ] as never);
  await render(true, ["ai.memory.view", "ai.memory.update"], "/chat", true);
  await click("添加内容");
  await click("个人记忆");
  expect(document.body.textContent).toContain("已隔离，待核对");
  expect(document.body.textContent).toContain("legacy_scope_unverified");
  const checkbox = (text: string) => [...document.querySelectorAll("label")].find(label => label.textContent?.includes(text))?.querySelector<HTMLInputElement>('input[type="checkbox"]');
  expect(checkbox("待核对事实")?.disabled).toBe(true);
  expect(checkbox("仍可本地使用")?.disabled).toBe(false);
  expect(document.body.textContent).toContain("soha://session/original/message/source");
  const correctionButtons = [...document.querySelectorAll<HTMLButtonElement>("button")].filter(button => button.textContent?.replace(/\s/g, "") === "改正");
  expect(correctionButtons[0].disabled).toBe(true);
  expect(correctionButtons[1].disabled).toBe(false);
  const deleteButton = [...document.querySelectorAll<HTMLButtonElement>("button")].find(button => button.textContent?.replace(/\s/g, "") === "删除");
  expect(deleteButton?.disabled).toBe(false);
  expect(assistantApi.saveMemory).not.toHaveBeenCalled();
});

it("reconciles a read-only stopped request without claiming terminality or locking new dsh messages", async () => {
  const owner = JSON.stringify([useAppStore.getState().host?.serverUrl || "", "user-1"]);
  const key = `soha.app.native-request.v1:${encodeURIComponent(owner)}/chat-main/legacy-stop`;
  localStorage.setItem(key, JSON.stringify({cancelPending: true}));
  const run = {id: "legacy-readonly", sessionId: "chat-main", providerKind: "native", status: "running", phase: "paused", output: {executionReadOnly: true, stopReason: "legacy_reconciliation_required"}};
  vi.mocked(assistantApi.findRequest).mockResolvedValueOnce(run as never);
  vi.mocked(assistantApi.chatTasks).mockResolvedValueOnce([run] as never);
  vi.mocked(assistantApi.events).mockResolvedValue({items: [], nextSequence: 0, hasMore: false, resyncRequired: false});
  await render(true, [], "/chat", true);
  await act(async () => { await new Promise(resolve => setTimeout(resolve, 30)); });
  expect(readPendingRequests(owner, "chat-main")).toEqual([]);
  expect(JSON.parse(localStorage.getItem(`soha.app.run-request.v2:${encodeURIComponent(owner)}/chat-main/legacy-stop`)!)).toMatchObject({cancelPending: true, acknowledged: true, runId: run.id});
  expect(localStorage.getItem(key)).toBe(JSON.stringify({cancelPending: true}));
  expect(document.querySelector<HTMLTextAreaElement>('textarea[aria-label="给助手发消息"]')?.disabled).toBe(false);
  expect(document.body.textContent).toContain("历史执行已隔离，等待核对");
  expect(client!.getQueryData<Array<{id: string; status: string}>>(["assistant-tasks", owner, true, "chat-main"])?.find(item => item.id === run.id)?.status).toBe("running");
  expect(assistantApi.cancel).not.toHaveBeenCalled();
  expect(streamAssistant).not.toHaveBeenCalled();
});

it("opens a main or older side Chat outside the recent list with only Chat permission", async () => {
  const recent = Array.from({ length: 20 }, (_, index) => ({
    id: `recent-${index}`, title: `近期话题 ${index}`, metadata: { conversationKind: "side" },
  }));
  vi.mocked(assistantApi.chatTasks).mockResolvedValue([]);
  vi.mocked(assistantApi.chatSessions).mockResolvedValue(recent as never);
  vi.mocked(assistantApi.session).mockResolvedValueOnce({
    id: "older", title: "旧旁聊", metadata: { conversationKind: "side" },
  } as never);
  try {
    const element = await render(true, [], "/chat?session=older", true);
    expect(assistantApi.session).toHaveBeenCalledExactlyOnceWith("older", false);
    expect(assistantApi.messages).toHaveBeenCalledWith("older");
    expect(assistantApi.chatTasks).toHaveBeenCalledWith("older");
    await vi.waitFor(() => expect(composerInput(element).disabled).toBe(false));
    await click("主聊天");
    expect(assistantApi.messages).toHaveBeenCalledWith("chat-main");
    expect(assistantApi.chatTasks).toHaveBeenCalledWith("chat-main");
    await vi.waitFor(() => expect(composerInput(element).disabled).toBe(false));
    expect(assistantApi.tasks).not.toHaveBeenCalled();
    expect(assistantApi.access).not.toHaveBeenCalled();
    expect(assistantApi.catalog).toHaveBeenCalled();
  } finally {
    vi.mocked(assistantApi.chatSessions).mockResolvedValue([
      { id: "chat-main", title: "普通 Chat", metadata: { conversationKind: "main" } },
    ] as never);
  }
});

it("does not read messages or tasks for a rejected Chat detail", async () => {
  const element = await render(true, [], "/chat?session=personal-side", true);
  expect(element.textContent).toContain("普通会话尚未读取或无权访问");
  expect(assistantApi.messages).not.toHaveBeenCalled();
  expect(assistantApi.chatTasks).not.toHaveBeenCalled();
});

it.each(["hermes", "custom-provider"])("omits dsh-only fields in ordinary %s Chat", async (agentProviderId) => {
  vi.mocked(assistantApi.session).mockResolvedValueOnce({
    id: "external", title: "外部助手", metadata: {
      conversationKind: "side", agentProviderId, modelPreferences: { publicModel: "old" },
    },
  } as never);
  vi.mocked(streamAssistant).mockResolvedValueOnce(undefined);
  const element = await render(true, [], "/chat?session=external", true);
  await enterMessage(element, "普通消息");
  await click("发送");
  const [session, request] = vi.mocked(streamAssistant).mock.calls[0];
  expect(session).toBe("external");
  expect(request).toMatchObject({ content: "普通消息", mode: "general" });
  expect(request).not.toHaveProperty("taskIntent");
  expect(request).not.toHaveProperty("modelPreferences");
  expect(request.agentProviderId).toBeUndefined();
  expect(readPendingRequests(selectAssistantOwner(useAppStore.getState()), session)).toEqual([]);
});

it.each([
  ["request_not_accepted", false, true],
  ["agent_unsupported", false, true],
  ["agent_failed", false, false],
  ["request_not_accepted", true, false],
] as const)("releases only pre-accept rejections (%s, accepted frame %s)", async (code, accepted, released) => {
  if (!released && !accepted)
    vi.mocked(assistantApi.findRequest).mockRejectedValueOnce(new Error("Request not yet visible"));
  vi.mocked(streamAssistant).mockImplementationOnce(async (session, _input, _signal, onEvent) => {
    if (accepted)
      onEvent({ id: "run-event", sessionId: session, runId: "accepted-run", type: "agent.status", providerKind: "dsh", providerId: "dsh", status: "queued", sequence: 1, createdAt: "2026-10-06T00:00:00Z" });
    throw new ApiError(200, code, "提交未完成");
  });
  const element = await render(true, [], "/chat", true);
  await enterMessage(element, "本轮消息");
  await click("发送");
  const owner = selectAssistantOwner(useAppStore.getState());
  const requestId = vi.mocked(streamAssistant).mock.calls[0][1].requestId!;
  const key = `soha.app.run-request.v2:${encodeURIComponent(owner!)}/chat-main/${requestId}`;
  expect(localStorage.getItem(key) === null).toBe(released);
  expect(composerInput(element).disabled).toBe(!released);
  expect(composerInput(element).value).toBe("本轮消息");
  expect(streamAssistant).toHaveBeenCalledTimes(1);
});

it("retries the exact cross-client Run after reload even when the task list omits it", async () => {
  const run = { id: "cross-client", sessionId: "chat-main", providerKind: "hermes", status: "running" };
  vi.mocked(assistantApi.chatTasks).mockResolvedValueOnce([run] as never);
  vi.mocked(assistantApi.cancel)
    .mockRejectedValueOnce(new Error("offline"))
    .mockResolvedValueOnce({ ...run, status: "canceled" } as never);
  await render(true, [], "/chat", true);
  await click("停止接收");
  await act(async () => root?.unmount());
  node?.remove();
  client?.clear();

  const element = await render(true, [], "/chat", true);
  expect(element.textContent).toContain("取消处理中");
  expect(composerInput(element).disabled).toBe(true);
  expect(assistantApi.cancel).toHaveBeenCalledTimes(1);
  await click("重试停止");
  expect(vi.mocked(assistantApi.cancel).mock.calls).toEqual([[run.id], [run.id]]);
  expect(assistantApi.findRequest).not.toHaveBeenCalled();
  expect(streamAssistant).not.toHaveBeenCalled();
  expect(composerInput(element).disabled).toBe(false);
});

it.each([false, true])("sends cleared or effort-only model preferences for dsh (clear=%s)", async (clear) => {
  vi.mocked(assistantApi.session).mockResolvedValueOnce({
    id: "model-chat", title: "模型设置", metadata: {
      conversationKind: "side", agentProviderId: "dsh",
      modelPreferences: clear ? { publicModel: "model-A", reasoningEffort: "high" } : { reasoningEffort: "high" },
    },
  } as never);
  vi.mocked(streamAssistant).mockResolvedValueOnce(undefined);
  const element = await render(true, ["observe.ai.view"], "/chat?session=model-chat", true);
  if (clear) {
    await click("模型与思考强度");
    await selectOption("模型", "默认模型");
    await click("模型与思考强度");
  }
  await enterMessage(element, "模型设置回归");
  await click("发送");
  expect(vi.mocked(streamAssistant).mock.calls[0][1].modelPreferences).toEqual(
    clear ? {} : { reasoningEffort: "high" },
  );
});

it.each([false, true])("keeps an external Run locked while cancellation awaits the runner (local stop=%s)", async (localStop) => {
  const running = { id: "external-stop", sessionId: "chat-main", providerKind: "hermes", status: "running" };
  const pending = { ...running, status: "canceled", output: { cancellationPending: true } };
  vi.mocked(assistantApi.chatTasks).mockResolvedValueOnce([localStop ? running : pending] as never);
  if (localStop) {
    vi.mocked(assistantApi.chatTasks).mockResolvedValueOnce([]);
    vi.mocked(assistantApi.cancel).mockResolvedValueOnce(pending as never);
  }
  const element = await render(true, [], "/chat", true);
  if (localStop) await click("停止接收");

  await waitForAssistantText(element, "取消处理中");
  expect(composerInput(element).disabled).toBe(true);
  expect(assistantApi.cancel).toHaveBeenCalledTimes(localStop ? 1 : 0);

  await act(async () => {
    client!.setQueryData(
      ["assistant-tasks", selectAssistantOwner(useAppStore.getState()), true, "chat-main"],
      [{ ...pending, output: { cancellationPending: false } }],
    );
  });
  await settleQueries();
  expect(element.textContent).not.toContain("取消处理中");
  expect(composerInput(element).disabled).toBe(false);
});

it("opens approved Heya main and old side conversations and tasks outside the recent list", async () => {
  vi.mocked(assistantApi.sessions).mockResolvedValueOnce([]);
  vi.mocked(assistantApi.tasks).mockResolvedValueOnce([{
    id: "old-side-run", sessionId: "heya-older", providerKind: "hermes", status: "completed",
    input: { question: "旧旁聊后台任务" },
  }] as never);
  vi.mocked(assistantApi.session).mockResolvedValueOnce({
    id: "heya-older", title: "旧 Heya 旁聊", metadata: { conversationKind: "personal_side" },
  } as never);
  const element = await render(true, [], "/assistant?session=heya-older");
  await waitForAssistantText(element, "旧 Heya 旁聊");
  await vi.waitFor(() => expect(composerInput(element).disabled).toBe(false));
  expect(assistantApi.session).toHaveBeenCalledWith("heya-older", true);
  expect(assistantApi.messages).toHaveBeenCalledWith("heya-older");
  await click("任务");
  await waitForAssistantText(element, "旧旁聊后台任务");
  await click("对话");
  await click("主聊天");
  expect(assistantApi.session).toHaveBeenCalledWith("main", true);
  expect(assistantApi.messages).toHaveBeenCalledWith("main");
});

it("does not read Heya deep-link detail without Heya approval", async () => {
  vi.mocked(assistantApi.access).mockResolvedValueOnce({ userId: "user-1", status: "pending", version: 1 });
  await render(true, [], "/assistant?session=heya-private");
  expect(assistantApi.session).not.toHaveBeenCalled();
  expect(assistantApi.messages).not.toHaveBeenCalled();
});

it.each(["detail", "messages"] as const)("hides cached Heya content after definitive %s rejection", async (endpoint) => {
  const detail = { id: "heya-private", title: "私密旧话题", metadata: { conversationKind: "personal_side" } };
  vi.mocked(assistantApi.session).mockResolvedValueOnce(detail as never);
  vi.mocked(assistantApi.messages).mockResolvedValueOnce([
    { id: "private", sessionId: detail.id, role: "assistant", content: "只在有权限时显示的私密内容", createdAt: "2026-10-06T00:00:00Z" },
  ]);
  const element = await render(true, [], "/assistant?session=heya-private");
  await waitForAssistantText(element, "只在有权限时显示的私密内容");
  const owner = selectAssistantOwner(useAppStore.getState());

  if (endpoint === "detail") {
    vi.mocked(assistantApi.session).mockRejectedValueOnce(new ApiError(503, "unavailable", "暂时不可用"));
    await act(async () => {
      await client!.refetchQueries({ queryKey: ["assistant-session", owner, false, detail.id] });
    });
    await waitForAssistantText(element, "会话读取失败");
    expect(element.textContent).toContain("只在有权限时显示的私密内容");
    vi.mocked(assistantApi.session).mockRejectedValueOnce(new ApiError(403, "forbidden", "已撤权"));
    await click("重新读取会话");
  } else {
    vi.mocked(assistantApi.messages).mockRejectedValueOnce(new ApiError(404, "not_found", "不存在"));
    await act(async () => {
      await client!.refetchQueries({ queryKey: ["assistant-messages", owner, detail.id] });
    });
  }

  await waitForAssistantText(element, "这个会话不属于 Heya");
  expect(element.textContent).not.toContain("只在有权限时显示的私密内容");
  expect(element.querySelector('textarea[aria-label="给助手发消息"]')).toBeNull();
  expect(streamAssistant).not.toHaveBeenCalled();
});

it("keeps approval from a persisted Native message read-only when its Run is missing", async () => {
  vi.mocked(assistantApi.chatTasks).mockResolvedValueOnce([]);
  vi.mocked(assistantApi.messages).mockResolvedValueOnce([{
    id: "native-message", sessionId: "chat-main", role: "assistant", content: "旧执行", createdAt: "2026-10-06T00:00:00Z",
    metadata: {
      agentRunId: "outside-list", agentStatus: { providerKind: "native" },
      toolExecutions: [{ toolName: "change.request", output: { relatedIds: { approvalRequestId: "historical-approval" } } }],
    },
  }]);
  vi.mocked(assistantApi.approvals).mockResolvedValueOnce({
    id: "historical-approval", toolName: "docker.projects.deploy.trigger",
    toolInput: { historicalInput: "旧冻结参数" }, status: "pending",
  } as never);
  const element = await render(true, [
    "ai.gateway.approvals.view", "ai.gateway.approvals.approve", "ai.gateway.approvals.reject", "ai.gateway.approvals.cancel",
  ], "/chat", true);
  await waitForAssistantText(element, "旧冻结参数");
  expect(element.querySelector(".app-assistant-approval button")).toBeNull();
  expect(assistantApi.decide).not.toHaveBeenCalled();
});

it("preserves the recent-list approval lock when the verified detail omits activity", async () => {
  const session = { id: "main", title: "主聊天", metadata: { conversationKind: "personal_main" } };
  vi.mocked(assistantApi.sessions).mockResolvedValueOnce([
    { ...session, activity: "waiting_approval" },
  ] as never);
  vi.mocked(assistantApi.tasks).mockResolvedValueOnce([]);
  const element = await render(true, [], "/assistant?session=main");
  await waitForAssistantText(element, "欢迎回来");
  expect(assistantApi.session).toHaveBeenCalledWith("main", true);
  expect(composerInput(element).disabled).toBe(true);

  await act(async () => {
    client!.setQueryData(["assistant-sessions", selectAssistantOwner(useAppStore.getState()), false], [session]);
  });
  await vi.waitFor(() => expect(composerInput(element).disabled).toBe(false));
});
