import type {
  PersonalAgentAccess,
  WorkbenchMessage,
  WorkbenchSession,
  WorkbenchAgentRun,
  WorkbenchAnalysisArtifact,
  WorkbenchSendMessageStreamRequest,
  WorkbenchStreamEvent,
  ApprovalRequest,
  AgentRunEventPage,
  AgentRunResumeRequest,
  WorkbenchCatalog,
  WorkbenchInspectionRun,
  ObservabilityMetricDefinition,
  KnowledgeBase,
  AIMemoryRecord,
  AIMemoryPolicy,
  AIMemoryWriteInput,
  PersonalEnvironment,
  PersonalEnvironmentActionRequest,
  PersonalEnvironmentDataDeletionRequest,
  PersonalEnvironmentTemplate,
  CapabilityTask,
  VirtualMachineAccessBinding,
  VirtualMachineSSHCommand,
  PersonalGuestRuntimeInput,
  PersonalGuestRuntime,
  PersonalWorkspaceRuntime,
  PersonalGuestToolsInput,
  VirtualizationOperation,
} from "@opensoha/contracts/gen/ts/sohaapi";
import {
  ApiError,
  assistantRequest,
  requestResponse,
  saveNativePersonalData,
} from "@/api";

type PersonalEnvironmentDataExportRequest = Pick<
  PersonalEnvironmentDataDeletionRequest,
  "assistantId" | "environmentVersion"
>;

// Native adapters require the source SDK combination until release verification.
export interface PersonalAssistant {
  id: string;
  name: string;
  mainSessionId: string;
  createdAt: string;
  updatedAt: string;
  avatarUrl?: string;
  avatarPosterUrl?: string;
  avatarMotion?: "auto" | "off";
}
export type AssistantAvatarInput = Required<
  Pick<PersonalAssistant, "avatarUrl" | "avatarPosterUrl" | "avatarMotion">
>;
export interface AssistantChatTask {
  kind: "avatar" | "undo";
  image?: AssistantAvatarInput;
  useCurrentAvatar?: boolean;
  publicModel?: string;
  messageId?: string;
}
export interface PersonalArtifact {
  id: string;
  sessionId?: string;
  messageId?: string;
  taskId?: string;
  artifact: WorkbenchAnalysisArtifact;
  createdAt: string;
}
export type AssistantSession = WorkbenchSession & {
  metadata?: WorkbenchSession["metadata"] & {
    conversationKind?: "main" | "side" | "personal_main" | "personal_side";
  };
};

export const assistantApi = {
  workspaceRuntime: async (assistantId: string) => {
    const result = await assistantRequest<PersonalWorkspaceRuntime>("/copilot/assistant/environment/runtime");
    if (result?.assistantId !== assistantId) throw new ApiError(502, "response_contract_mismatch", "运行状态与助手不匹配");
    return result;
  },
  runtime: async (assistantId: string, input: PersonalGuestRuntimeInput) => {
    const result = await assistantRequest<PersonalGuestRuntime>("/copilot/assistant/environment/runtime", {method: "POST", body: JSON.stringify(input)});
    if (result?.assistantId !== assistantId) throw new ApiError(502, "response_contract_mismatch", "运行回执与助手不匹配");
    return result;
  },
  runtimeReceipt: async (assistantId: string, id: string) => {
    const result = await assistantRequest<PersonalGuestRuntime>(`/copilot/assistant/environment/runtime/${encodeURIComponent(id)}`);
    if (result?.assistantId !== assistantId || result.id !== id) throw new ApiError(502, "response_contract_mismatch", "原运行回执不匹配");
    return result;
  },
  guestTools: (input: PersonalGuestToolsInput) => assistantRequest<VirtualizationOperation>("/copilot/assistant/environment/guest-tools", {method: "POST", body: JSON.stringify(input)}),
  guestToolsOperation: (id: string) => assistantRequest<VirtualizationOperation>(`/virtualization/operations/${encodeURIComponent(id)}`),
  capabilityTask: (id: string, signal?: AbortSignal) =>
    assistantRequest<CapabilityTask>(`/ai-gateway/tasks/${encodeURIComponent(id)}`, { signal }),
  vmAccessBinding: (id: string, signal?: AbortSignal) =>
    assistantRequest<VirtualMachineAccessBinding>(`/virtualization/vms/${encodeURIComponent(id)}/access-binding`, { signal }),
  vmSSHCommand: (id: string, signal?: AbortSignal) =>
    assistantRequest<VirtualMachineSSHCommand>(`/virtualization/ssh-commands/${encodeURIComponent(id)}`, { signal }),
  cancelVMSSHCommand: (id: string) =>
    assistantRequest<VirtualMachineSSHCommand>(`/virtualization/ssh-commands/${encodeURIComponent(id)}`, { method: "DELETE" }),
  access: () =>
    assistantRequest<PersonalAgentAccess>("/copilot/assistant/access"),
  requestAccess: () =>
    assistantRequest<PersonalAgentAccess>("/copilot/assistant/access", {
      method: "POST",
      body: "{}",
    }),
  exportEnvironmentData: async (
    input: PersonalEnvironmentDataExportRequest,
    signal: AbortSignal,
  ) => {
    if ((await saveNativePersonalData(input, signal)) !== null) return null;
    const response = await requestResponse(
      "/copilot/assistant/environment/export",
      { method: "POST", body: JSON.stringify(input), signal },
      true,
      false,
    );
    const size = Number(response.headers.get("Content-Length"));
    const digest = response.headers.get("X-Content-SHA256") || "";
    if (
      response.headers.get("X-Assistant-ID") !== input.assistantId ||
      !Number.isSafeInteger(size) ||
      size < 1 ||
      size > 256 * 1048576 ||
      !/^[a-f0-9]{64}$/.test(digest) ||
      !response.body
    ) {
      throw new Error("个人数据导出回执不完整或与助手不匹配");
    }
    const reader = response.body.getReader();
    const parts: Uint8Array<ArrayBuffer>[] = [];
    let received = 0;
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        received += value.byteLength;
        if (received > size || signal.aborted)
          throw new Error("个人数据导出已中止或超过边界");
        parts.push(new Uint8Array(value));
      }
    } finally {
      await reader.cancel();
    }
    const blob = new Blob(parts, { type: "application/x-tar" });
    const actual = Array.from(
      new Uint8Array(
        await crypto.subtle.digest("SHA-256", await blob.arrayBuffer()),
      ),
      (byte) => byte.toString(16).padStart(2, "0"),
    ).join("");
    if (received !== size || actual !== digest || signal.aborted)
      throw new Error("个人数据导出被截断或摘要不匹配");
    return blob;
  },
  deleteEnvironmentData: async (
    input: PersonalEnvironmentDataDeletionRequest,
  ) => {
    const result = await assistantRequest<PersonalEnvironment>(
      "/copilot/assistant/environment",
      { method: "DELETE", body: JSON.stringify(input) },
    );
    if (result?.assistantId !== input.assistantId)
      throw new ApiError(
        502,
        "response_contract_mismatch",
        "个人环境回执与助手不匹配",
      );
    return result;
  },
  environmentTemplates: () =>
    assistantList<PersonalEnvironmentTemplate>(
      "/copilot/assistant/environment/templates",
    ),
  changeEnvironment: async (
    assistantId: string,
    input: PersonalEnvironmentActionRequest,
  ) => {
    const result = await assistantRequest<PersonalEnvironment>(
      "/copilot/assistant/environment",
      { method: "POST", body: JSON.stringify(input) },
    );
    if (result?.assistantId !== assistantId)
      throw new ApiError(
        502,
        "response_contract_mismatch",
        "个人环境回执与助手不匹配",
      );
    return result;
  },
  environment: async (assistantId: string) => {
    const result = await assistantRequest<PersonalEnvironment>(
      "/copilot/assistant/environment",
    );
    if (result?.assistantId !== assistantId)
      throw new ApiError(
        502,
        "response_contract_mismatch",
        "个人环境回执与助手不匹配",
      );
    return result;
  },
  catalog: () =>
    assistantRequest<WorkbenchCatalog>("/copilot/workbench/catalog"),
  metrics: (dataSourceId: string) =>
    assistantList<ObservabilityMetricDefinition>(
      `/observability/metrics/catalog?dataSourceId=${encodeURIComponent(dataSourceId)}`,
    ),
  inspections: () =>
    assistantList<WorkbenchInspectionRun>("/copilot/inspection-runs"),
  knowledgeBases: () => assistantList<KnowledgeBase>("/ai/knowledge-bases"),
  memories: () => assistantList<AIMemoryRecord>("/ai/memory"),
  memoryPolicies: () => assistantList<AIMemoryPolicy>("/ai/memory/policies"),
  saveMemory: (input: AIMemoryWriteInput) =>
    assistantRequest<AIMemoryRecord>("/ai/memory", {
      method: "POST",
      body: JSON.stringify(input),
    }),
  deleteMemory: (id: string) =>
    requestResponse(`/ai/memory/${encodeURIComponent(id)}`, {
      method: "DELETE",
    }).then(() => undefined),
  ensure: () =>
    assistantRequest<PersonalAssistant>("/copilot/assistant", {
      method: "POST",
      body: "{}",
    }),
  rename: (name: string) =>
    assistantRequest<PersonalAssistant>("/copilot/assistant", {
      method: "PATCH",
      body: JSON.stringify({ name }),
    }),
  avatar: (input: AssistantAvatarInput) =>
    assistantRequest<PersonalAssistant>("/copilot/assistant/avatar", {
      method: "PATCH",
      body: JSON.stringify(input),
    }),
  generateAvatar: async (
    provider: string,
    model: string,
    prompt: string,
    signal: AbortSignal,
  ) => {
    const response = await requestResponse(
      `/ai-gateway/llm/${encodeURIComponent(provider)}/v1/images/generations`,
      {
        method: "POST",
        signal,
        body: JSON.stringify({ model, prompt, n: 1, size: "1024x1024" }),
      },
    );
    return response.json() as Promise<{
      data?: { b64_json?: string; url?: string }[];
    }>;
  },
  sessions: () =>
    assistantList<AssistantSession>("/copilot/assistant/sessions"),
  messages: (id: string) =>
    assistantList<WorkbenchMessage>(
      `/copilot/sessions/${encodeURIComponent(id)}/messages`,
    ),
  side: (title: string) =>
    assistantRequest<AssistantSession>("/copilot/assistant/sessions", {
      method: "POST",
      body: JSON.stringify({ title, mode: "general", source: "workbench" }),
    }),
  tasks: () => assistantList<WorkbenchAgentRun>("/copilot/assistant/tasks"),
  findRequest: async (sessionId: string, requestId: string) => {
    const run = await assistantRequest<WorkbenchAgentRun>(
      `/copilot/sessions/${encodeURIComponent(sessionId)}/native-request?requestId=${encodeURIComponent(requestId)}`,
    );
    if (run?.sessionId !== sessionId || run?.providerKind !== "native")
      throw new ApiError(
        502,
        "response_contract_mismatch",
        "恢复回执与原会话或任务不匹配",
      );
    return run;
  },
  events: async (id: string, afterSequence: number, signal?: AbortSignal) => {
    const page = await assistantRequest<AgentRunEventPage>(
      `/copilot/agent-runs/${encodeURIComponent(id)}/events?afterSequence=${afterSequence}`,
      { signal },
    );
    if (
      !page ||
      !Array.isArray(page.items) ||
      page.items.length > 100 ||
      !Number.isSafeInteger(page.nextSequence) ||
      page.nextSequence < 0 ||
      typeof page.hasMore !== "boolean" ||
      typeof page.resyncRequired !== "boolean"
    )
      throw new ApiError(
        502,
        "response_contract_mismatch",
        "Invalid task events",
      );
    if (page.resyncRequired) {
      if (page.items.length)
        throw new ApiError(
          502,
          "response_contract_mismatch",
          "Invalid task resync",
        );
      return page;
    }
    let previous = afterSequence;
    for (const event of page.items) {
      if (
        !event ||
        event.runId !== id ||
        typeof event.sessionId !== "string" ||
        !Number.isSafeInteger(event.sequence) ||
        event.sequence <= previous ||
        event.sequence > page.nextSequence ||
        typeof event.type !== "string" ||
        (event.type === "message.delta" &&
          (typeof event.messageId !== "string" ||
            typeof event.contentDelta !== "string")) ||
        (event.type === "message.done" &&
          (typeof event.messageId !== "string" ||
            typeof event.content !== "string"))
      )
        throw new ApiError(
          502,
          "response_contract_mismatch",
          "Invalid task event sequence",
        );
      previous = event.sequence;
    }
    if (
      page.nextSequence < previous ||
      (page.hasMore && page.nextSequence === afterSequence)
    )
      throw new ApiError(
        502,
        "response_contract_mismatch",
        "Invalid task event cursor",
      );
    return page;
  },
  resume: (id: string, input: AgentRunResumeRequest) =>
    assistantRequest<WorkbenchAgentRun>(
      `/copilot/agent-runs/${encodeURIComponent(id)}/resume`,
      { method: "POST", body: JSON.stringify(input) },
    ),
  artifacts: () =>
    assistantList<PersonalArtifact>("/copilot/assistant/artifacts"),
  cancel: (id: string) =>
    assistantRequest<WorkbenchAgentRun>(
      `/copilot/agent-runs/${encodeURIComponent(id)}/cancel`,
      { method: "POST", body: "{}" },
    ),
  approvals: async (id: string) => {
    const items = await assistantList<ApprovalRequest>(
      `/ai-gateway/approval-requests?id=${encodeURIComponent(id)}`,
    );
    return items.find((item) => item.id === id);
  },
  decide: (id: string, action: "approve" | "reject" | "cancel") =>
    assistantRequest(
      `/ai-gateway/approval-requests/${encodeURIComponent(id)}/${action}`,
      { method: "POST", body: "{}" },
    ),
};

async function assistantList<T>(path: string): Promise<T[]> {
  const payload = (await (await requestResponse(path)).json()) as {
    items?: T[] | null;
    data?: T[];
  };
  // Existing Core versions encode empty Go slices as null.
  const items =
    payload?.items === null ? [] : (payload?.items ?? payload?.data);
  if (!Array.isArray(items) || items.length > 1000)
    throw new ApiError(
      502,
      "response_contract_mismatch",
      "Invalid assistant list response",
    );
  return items;
}

export function parseAssistantFrames(input: string): {
  events: WorkbenchStreamEvent[];
  rest: string;
} {
  if (input.length > 1 << 20) throw new Error("Assistant event is too large");
  const frames = input.split(/\r?\n\r?\n/);
  const events: WorkbenchStreamEvent[] = [];
  for (const frame of frames.slice(0, -1)) {
    const data = frame
      .split(/\r?\n/)
      .filter((line) => line.startsWith("data:"))
      .map((line) => line.slice(5).trimStart())
      .join("\n");
    if (!data || data === "[DONE]") continue;
    const event = JSON.parse(data) as WorkbenchStreamEvent;
    if (
      !event ||
      typeof event.type !== "string" ||
      typeof event.sessionId !== "string" ||
      typeof event.sequence !== "number"
    )
      throw new Error("Invalid assistant event");
    events.push(event);
  }
  return { events, rest: frames.at(-1) ?? "" };
}

export async function streamAssistant(
  id: string,
  input: WorkbenchSendMessageStreamRequest & {
    assistantTask?: AssistantChatTask;
  },
  signal: AbortSignal,
  onEvent: (event: WorkbenchStreamEvent) => void,
) {
  const response = await requestResponse(
    `/copilot/sessions/${encodeURIComponent(id)}/messages/stream`,
    {
      method: "POST",
      body: JSON.stringify(input),
      headers: { Accept: "text/event-stream" },
      signal,
    },
  );
  if (
    !response.headers.get("content-type")?.includes("text/event-stream") ||
    !response.body
  )
    throw new Error("Streaming is unavailable");
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  const seen = new Set<string>();
  let rest = "",
    terminal = false;
  try {
    while (true) {
      const chunk = await reader.read();
      const parsed = parseAssistantFrames(
        rest + decoder.decode(chunk.value, { stream: !chunk.done }),
      );
      rest = parsed.rest;
      for (const event of parsed.events) {
        if (event.sessionId !== id)
          throw new Error("Assistant conversation mismatch");
        const key = `${event.sequence}:${event.id}`;
        if (seen.has(key)) continue;
        seen.add(key);
        if (seen.size > 10000)
          throw new Error("Assistant stream exceeds limit");
        if (event.type === "error") throw new Error(event.message);
        terminal ||=
          event.type === "message.done" ||
          (event.type === "agent.status" &&
            ["queued", "succeeded", "failed", "cancelled"].includes(
              event.status,
            ));
        onEvent(event);
      }
      if (chunk.done) break;
    }
    if (rest.trim() || !terminal)
      throw new Error(
        "Assistant stream ended unexpectedly; reload messages before retrying",
      );
  } finally {
    await reader.cancel().catch(() => undefined);
    reader.releaseLock();
  }
}
