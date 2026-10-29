import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { App, ConfigProvider } from "antd";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { AssistantPage } from "@/assistant";
import { assistantApi, streamAssistant } from "@/assistant-api";
import { selectAssistantOwner, useAppStore } from "@/store";
import * as imageHelpers from "@/assistant-avatar-image";
import {
  readPendingRequests,
  savePendingRequest,
} from "@/assistant-request-recovery";

vi.mock("@/assistant-api", () => ({
  assistantApi: {
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
  client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  await act(async () => {
    root!.render(
      <QueryClientProvider client={client!}>
        <ConfigProvider>
          <App>
            <MemoryRouter initialEntries={[entry]}>
              <AssistantPage />
            </MemoryRouter>
          </App>
        </ConfigProvider>
      </QueryClientProvider>,
    );
    await new Promise((resolve) => setTimeout(resolve, 20));
  });
  await act(async () => {
    await new Promise((resolve) => setTimeout(resolve, 20));
  });
  for (let attempt = 0, stable = 0; attempt < 40 && stable < 2; attempt++) {
    await act(async () => {
      await new Promise((resolve) => setTimeout(resolve, 10));
    });
    stable = client.isFetching() ? 0 : stable + 1;
  }
  return node;
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
    await new Promise((resolve) => setTimeout(resolve, 20));
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
    await new Promise((resolve) => setTimeout(resolve, 20));
  });
  const option = [
    ...document.body.querySelectorAll<HTMLElement>(".ant-select-item-option"),
  ].find(
    (item) =>
      !item.closest(".ant-select-dropdown-hidden") &&
      (label === "模型"
        ? item.querySelector(".ant-select-item-option-content")?.textContent ===
          text
        : item.textContent?.includes(text)),
  )!;
  expect(option).toBeTruthy();
  await act(async () => {
    option.click();
    await new Promise((resolve) => setTimeout(resolve, 20));
  });
}

describe("personal assistant App", () => {
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
    expect(element.textContent).toContain("等待管理员批准");
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
        await new Promise((resolve) => setTimeout(resolve, 20));
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
      await new Promise((resolve) => setTimeout(resolve, 30));
    });
    expect(streamAssistant).toHaveBeenCalledTimes(1);
    expect(vi.mocked(streamAssistant).mock.calls[0][1]).toMatchObject({
      content: "调查发布失败",
      agentProviderId: "internal",
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
    expect(vi.mocked(streamAssistant).mock.calls[1][1].taskIntent).toEqual({
      capabilities: [],
    });
    expect(assistantApi.metrics).toHaveBeenCalledWith("metrics-source");
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
  it("recovers Native events and resumes the same run without sending a new message", async () => {
    const timestamp = "2026-10-08T00:00:00Z";
    const run = {
      id: "native-run",
      sessionId: "main",
      providerId: "internal",
      providerKind: "native",
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
  it("shows Native approvals and keeps an acknowledged cancellation pending", async () => {
    const timestamp = "2026-10-08T00:00:00Z";
    const run = {
      id: "native-approval-run",
      sessionId: "side",
      providerId: "internal",
      providerKind: "native",
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
