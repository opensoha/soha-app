import { useCallback, useEffect, useRef, useState } from "react";
import {
  App,
  Alert,
  Button,
  Drawer,
  Empty,
  Input,
  Image,
  Modal,
  Popover,
  Segmented,
  Select,
  Space,
  Spin,
  Tag,
  Typography,
} from "antd";
import {
  CommentOutlined,
  ExperimentOutlined,
  FileTextOutlined,
  MenuUnfoldOutlined,
  PlusOutlined,
  PictureOutlined,
  ArrowUpOutlined,
  StopOutlined,
  SmileOutlined,
  UnorderedListOutlined,
  UserOutlined,
} from "@ant-design/icons";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useSearchParams } from "react-router-dom";
import type {
  WorkbenchAgentRun,
  WorkbenchAnalysisArtifact,
  WorkbenchMessage,
  WorkbenchTaskIntent,
  PersonalEnvironment,
  WorkbenchImageAttachment,
} from "@opensoha/contracts/gen/ts/sohaapi";
import {
  prepareAssistantAvatar,
  prepareChatImage,
} from "./assistant-avatar-image";
import type { AssistantChatTask } from "./assistant-api";
import type { TextAreaRef } from "antd/es/input/TextArea";
import { ApiError } from "@/api";
import {
  isActiveRun,
  isCancellationPending,
  isReadOnlyRun,
  isDurableRun,
  isTerminalRun,
  assistantApi,
  streamAssistant,
} from "@/assistant-api";
import { selectAssistantOwner, useAppStore } from "@/store";
import { openBrowserURL } from "@/native/host";
import { AssistantRuntimeAssembly, AssistantRuntimeProfileControl } from "./assistant-runtime-profile";
import { RunTaskProgress } from "@/assistant-native-task";
import { useRequestRecovery } from "@/assistant-request-recovery";
import { AssistantAvatar, AssistantProfile } from "@/assistant-profile";
import { AssistantWorkspace as PersonalVMWorkspace } from "@/assistant-workspace";
import { ProfessionalTask } from "@/assistant-professional-task";
import {
  hasMemoryDegradation,
  AssistantBackground,
  AssistantModel,
  MessageBackground,
  AssistantContextUsage,
  TaskUsage,
  MemoryEditor,
  sessionBackground,
  type AssistantBackgroundSelection,
} from "@/assistant-background";
import "./assistant.css";

type Section = "chat" | "tasks" | "results" | "me";

function isRunSystemReply(item: WorkbenchMessage) {
  return item.role === "system" && typeof item.metadata?.agentRunId === "string" &&
    Boolean(item.metadata.agentRunId);
}

function messageImages(item: WorkbenchMessage): WorkbenchImageAttachment[] {
  const images = item.metadata?.images;
  return Array.isArray(images)
    ? images.filter((image): image is WorkbenchImageAttachment =>
        Boolean(
          image &&
          typeof image === "object" &&
          "dataUrl" in image &&
          typeof image.dataUrl === "string" &&
          image.dataUrl.length <= 700000 &&
          /^data:image\/(png|jpeg);base64,[A-Za-z0-9+/]+=*$/.test(
            image.dataUrl,
          ),
        ),
      )
    : [];
}

function messageReaction(
  messages: WorkbenchMessage[],
  target: WorkbenchMessage,
) {
  const reply = [...messages]
    .reverse()
    .find(
      (item) =>
        item.role === "assistant" &&
        item.sessionId === target.sessionId &&
        item.metadata?.requestMessageId === target.id,
    );
  const emoji = reply?.metadata?.assistantReaction;
  return typeof emoji === "string" &&
    ["👋", "👍", "❤️", "😊", "🎉", "💡", "👀", "🤔", "✅", "🙏"].includes(emoji)
    ? emoji
    : undefined;
}
const sections = [
  { value: "chat", label: "对话", icon: <CommentOutlined /> },
  { value: "tasks", label: "任务", icon: <UnorderedListOutlined /> },
  { value: "results", label: "成果", icon: <FileTextOutlined /> },
  { value: "me", label: "我的", icon: <UserOutlined /> },
];
const statusNames: Record<string, string> = {
  queued: "等待执行",
  running: "执行中",
  completed: "已完成",
  failed: "失败",
  canceled: "已取消",
  callback_timeout: "回调超时",
};

const environmentNames: Record<PersonalEnvironment["state"], string> = {
  unprovisioned: "未开通",
  pending: "正在处理",
  ready: "就绪",
  sleeping: "休眠",
  missing: "环境缺失",
  expired: "租约已到期",
  unknown: "状态未确认",
  quota_exceeded: "配额已耗尽",
  deleting: "正在删除数据",
  deletion_unknown: "数据删除结果未确认",
  deleted: "持久数据已删除",
};

async function readConversation<T>(read: () => Promise<T>) {
  try {
    return await read();
  } catch (error) {
    if (error instanceof ApiError && (error.status === 403 || error.status === 404))
      return null;
    throw error;
  }
}

export function AssistantPage({ ordinary = false }: { ordinary?: boolean }) {
  const owner = useAppStore(selectAssistantOwner);
  return <AssistantWorkspace key={`${owner}:${ordinary}`} ordinary={ordinary} />;
}

function AssistantWorkspace({ ordinary }: { ordinary: boolean }) {
  const { message } = App.useApp();
  const client = useQueryClient();
  const bootstrap = useAppStore((state) => state.bootstrap);
  const serverUrl = useAppStore((state) => state.host?.serverUrl);
  const canExportData = useAppStore((state) =>
    ["darwin", "linux", "windows"].includes(state.host?.app.platform ?? ""),
  );
  const owner = useAppStore(selectAssistantOwner);
  const canChat =
    bootstrap?.permissionSnapshot.permissionKeys.includes("observe.ai.chat") ??
    false;
  const [params, setParams] = useSearchParams();
  const [addOpen, setAddOpen] = useState(false);
  const [section, setSection] = useState<Section>("chat");
  const [environmentTemplate, setEnvironmentTemplate] = useState<string>();
  const [deletionTarget, setDeletionTarget] = useState<{
    id: string;
    name: string;
    version: number;
  }>();
  const [deletionName, setDeletionName] = useState("");
  const [deletionReconciled, setDeletionReconciled] = useState("");
  const [topics, setTopics] = useState(false);
  const [sideOpen, setSideOpen] = useState(false);
  const [professionalOpen, setProfessionalOpen] = useState(false);
  const [streamingRuntime, setStreamingRuntime] = useState<
    Record<string, { assembly?: unknown; hooks?: unknown } | undefined>
  >({});
  const [backgrounds, setBackgrounds] = useState<
    Record<string, AssistantBackgroundSelection>
  >({});
  const [memoryDraft, setMemoryDraft] = useState<{
    fact: string;
    refs: string[];
  }>();
  const [title, setTitle] = useState("");
  const [appearanceDrafts, setAppearanceDrafts] = useState<
    Record<string, AssistantChatTask | undefined>
  >({});
  const [heldDrafts, setHeldDrafts] = useState<
    Record<string, string | undefined>
  >({});
  const [preparingImage, setPreparingImage] = useState(false);
  const [chatImages, setChatImages] = useState<
    Record<string, WorkbenchImageAttachment[] | undefined>
  >({});
  const composer = useRef<TextAreaRef>(null);
  const imagePicker = useRef<HTMLInputElement>(null);
  const [drafts, setDrafts] = useState<Record<string, string>>({});
  const [live, setLive] = useState<Record<string, string>>({});
  const [pending, setPending] = useState<Record<string, boolean>>({});
  const [memoryWarnings, setMemoryWarnings] = useState<Record<string, boolean>>({});
  const [stopping, setStopping] = useState<Record<string, boolean>>({});
  const [profileChecks, setProfileChecks] = useState<Record<string, {
    requested: string;
    status: "checking" | "unavailable" | "saved" | "observed";
  }>>({});
  const [result, setResult] = useState<WorkbenchAnalysisArtifact>();
  const streams = useRef<Record<string, AbortController>>({});
  const runIds = useRef<Record<string, string>>({});
  const runMessageStates = useRef(new Map<string, "active" | "refreshed">());
  const requests = useRef<Record<string, { content: string; id: string; recoverable: boolean }>>({});
  const bottom = useRef<HTMLDivElement>(null);
  const access = useQuery({
    queryKey: ["personal-agent-access", owner],
    queryFn: () => readConversation(assistantApi.access),
    enabled: !ordinary && canChat && Boolean(owner),
    retry: false,
    refetchInterval: 5000,
  });
  const canUseAgent = !ordinary && canChat && access.data?.status === "approved";
  const enabled = ordinary ? canChat : canUseAgent;
  const main = useQuery({ queryKey: ["ordinary-main", owner], queryFn: assistantApi.chatMain, enabled: ordinary && canChat, retry: false });
  const requestAccess = useMutation({
    mutationFn: assistantApi.requestAccess,
    onSuccess: () =>
      client.invalidateQueries({ queryKey: ["personal-agent-access", owner] }),
    onError: (err: Error) => void message.error(err.message),
  });
  const assistant = useQuery({
    queryKey: ["personal-assistant", owner],
    queryFn: assistantApi.ensure,
    retry: false,
    enabled: canUseAgent && Boolean(owner),
  });
  const environment = useQuery({
    queryKey: ["assistant-environment", owner, assistant.data?.id],
    queryFn: () => assistantApi.environment(assistant.data!.id),
    enabled:
      canUseAgent && Boolean(owner && assistant.data?.id) && section === "me",
    retry: false,
    refetchInterval: 5000,
  });
  const personalVMPending =
    environment.data?.backend === "vm" && environment.data.state === "pending";
  const environmentTemplates = useQuery({
    queryKey: ["assistant-environment-templates", owner, assistant.data?.id],
    queryFn: assistantApi.environmentTemplates,
    enabled:
      canUseAgent &&
      Boolean(owner && assistant.data?.id) &&
      section === "me" &&
      !environment.isError &&
      environment.data?.state === "unprovisioned",
    retry: false,
  });
  const selectedEnvironmentTemplate = environmentTemplates.data?.find(
    (item) => item.id === environmentTemplate,
  );
  const environmentChange = useMutation({
    mutationFn: (input: Parameters<typeof assistantApi.changeEnvironment>[1]) =>
      assistantApi.changeEnvironment(assistant.data!.id, input),
    retry: false,
    onSuccess: (result, input) => {
      if (input.action === "reconcile" && result?.state === "deletion_unknown")
        setDeletionReconciled(`${result.assistantId}:${result.version}`);
    },
    onSettled: () =>
      client.invalidateQueries({ queryKey: ["assistant-environment"] }),
    onError: () =>
      void message.error("环境操作未确认，请核对最新状态；不会自动重试。"),
  });
  const environmentDeletion = useMutation({
    mutationFn: assistantApi.deleteEnvironmentData,
    retry: false,
    onSettled: async () => {
      await Promise.all([
        client.invalidateQueries({ queryKey: ["assistant-environment"] }),
        client.invalidateQueries({ queryKey: ["personal-assistant", owner] }),
      ]);
    },
    onError: () =>
      void message.error("数据删除结果未确认，请核对最新状态；不会自动重试。"),
  });
  const environmentExportAbort = useRef<AbortController | null>(null);
  useEffect(
    () => () => environmentExportAbort.current?.abort(),
    [owner, assistant.data?.id],
  );
  const environmentExport = useMutation({
    mutationFn: (
      input: Parameters<typeof assistantApi.exportEnvironmentData>[0],
    ) => {
      if (!canExportData)
        throw new Error("当前设备暂不支持文件导出，请使用桌面端或 Web。");
      const controller = new AbortController();
      environmentExportAbort.current = controller;
      return assistantApi.exportEnvironmentData(input, controller.signal);
    },
    retry: false,
    onSuccess: (blob) => {
      if (!blob || environmentExportAbort.current?.signal.aborted) return;
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = "personal-data.tar";
      anchor.click();
      URL.revokeObjectURL(url);
    },
    onSettled: () =>
      client.invalidateQueries({ queryKey: ["assistant-environment"] }),
    onError: () =>
      void message.error("数据导出未完成，请核对环境后再试；不会自动重试。"),
  });
  const environmentBusy =
    environmentChange.isPending ||
    environmentDeletion.isPending ||
    environmentExport.isPending;
  const sessions = useQuery({
    queryKey: ["assistant-sessions", owner, ordinary],
    queryFn: ordinary ? assistantApi.chatSessions : assistantApi.sessions,
    enabled,
    refetchInterval: 5000,
  });
  const mainSessionId = ordinary ? main.data?.id : assistant.data?.mainSessionId;
  const selectedId = params.get("session");
  const id = selectedId || mainSessionId || "";
  const listedSession = sessions.data?.find((item) => item.id === id);
  const ordinaryMain = ordinary && id === mainSessionId ? main.data : undefined;
  const detailKey = ["assistant-session", owner, ordinary, id];
  const profileCheck = profileChecks[id];
  const profileUnconfirmed = profileCheck?.status === "checking" || profileCheck?.status === "unavailable";
  const needsDetail = enabled && Boolean(id) && (Boolean(selectedId) ||
    Boolean(profileCheck) || client.getQueryData(detailKey) === null || (!listedSession && !ordinaryMain && !sessions.isPending));
  const detail = useQuery({
    queryKey: detailKey,
    queryFn: () => readConversation(() => assistantApi.session(id, !ordinary)),
    enabled: needsDetail && !profileUnconfirmed,
    retry: false,
    staleTime: profileCheck ? 5000 : 0,
    refetchInterval: 5000,
  });
  const detailUnavailable = needsDetail && detail.data === null;
  const current = needsDetail && (!profileUnconfirmed || detail.data !== undefined)
    ? detail.data ?? undefined
    : listedSession ?? ordinaryMain;
  const canUseSession = enabled && Boolean(current);
  const usesDsh = !current?.metadata?.agentProviderId ||
    ["dsh", "internal", "native"].includes(current.metadata.agentProviderId);
  const runtimeProfiles = useQuery({
    queryKey: ["assistant-runtime-profiles", owner],
    queryFn: assistantApi.runtimeProfiles,
    enabled: canUseSession && usesDsh,
    retry: false,
  });
  const scope = ordinary ? "chat" : "heya";
  const profileId = current?.metadata?.runtimeProfileId ?? "";
  const runtimeProfile = runtimeProfiles.isSuccess ? runtimeProfiles.data.find(
    (profile) => profile.enabled && profile.scope === scope && profile.id === (profileId || `${scope}-default`),
  ) : undefined;
  const updateSession = (sessionId: string, session: typeof detail.data) => {
    client.setQueryData(["assistant-session", owner, ordinary, sessionId], session);
    client.setQueryData<typeof sessions.data>(["assistant-sessions", owner, ordinary], (items) =>
      session ? items?.map((item) => item.id === sessionId ? session : item) : items,
    );
    if (session && ordinary && sessionId === mainSessionId)
      client.setQueryData(["ordinary-main", owner], session);
  };
  const checkRuntimeProfile = async (sessionId: string, requested: string) => {
    if (owner !== selectAssistantOwner(useAppStore.getState())) return;
    setProfileChecks((checks) => ({ ...checks, [sessionId]: { requested, status: "checking" } }));
    const queryKey = ["assistant-session", owner, ordinary, sessionId];
    await client.cancelQueries({ queryKey, exact: true });
    if (owner !== selectAssistantOwner(useAppStore.getState())) return;
    try {
      const session = await readConversation(() => assistantApi.session(sessionId, !ordinary));
      if (owner !== selectAssistantOwner(useAppStore.getState())) return;
      updateSession(sessionId, session);
      const status = session && (session.metadata?.runtimeProfileId ?? "") === requested ? "saved" : "observed";
      setProfileChecks((checks) => ({ ...checks, [sessionId]: { requested, status } }));
    } catch {
      if (owner !== selectAssistantOwner(useAppStore.getState())) return;
      setProfileChecks((checks) => ({ ...checks, [sessionId]: { requested, status: "unavailable" } }));
    }
  };
  const selectProfile = useMutation({
    mutationFn: ({ sessionId, profileId }: { sessionId: string; profileId: string }) =>
      assistantApi.selectRuntimeProfile(sessionId, profileId),
    onSuccess: async (session, { sessionId }) => {
      await client.cancelQueries({ queryKey: ["assistant-session", owner, ordinary, sessionId], exact: true });
      if (owner !== selectAssistantOwner(useAppStore.getState())) return;
      updateSession(sessionId, session);
      setProfileChecks((checks) => ({ ...checks, [sessionId]: { requested: session.metadata?.runtimeProfileId ?? "", status: "saved" } }));
    },
    onError: (_error, { sessionId, profileId }) => checkRuntimeProfile(sessionId, profileId),
  });
  const selectingCurrentProfile = selectProfile.isPending && selectProfile.variables?.sessionId === id;
  const canOpenProfileSettings = Boolean(
    serverUrl && bootstrap?.permissionSnapshot.permissionKeys.includes("settings.ai.view"),
  );
  const openProfileSettings = (profileId: string) => {
    const target = new URL("/ai-workbench/model-settings", serverUrl);
    target.searchParams.set("runtimeProfile", profileId);
    void openBrowserURL(target.href).catch(() => message.error("无法在浏览器中打开运行配置"));
  };
  const taskQueryKey = ordinary ? ["assistant-tasks", owner, true, id] : ["assistant-tasks", owner, false];
  const tasks = useQuery({
    queryKey: taskQueryKey,
    queryFn: () => ordinary ? assistantApi.chatTasks(id) : assistantApi.tasks(),
    enabled: ordinary ? canUseSession : canUseAgent,
    refetchInterval: 5000,
  });
  const artifacts = useQuery({
    queryKey: ["assistant-artifacts", owner],
    queryFn: assistantApi.artifacts,
    enabled: canUseAgent && section === "results",
    refetchInterval: 5000,
  });
  useEffect(() => {
    if (ordinary && main.data?.id)
      void client.invalidateQueries({queryKey: ["assistant-sessions", owner, ordinary]});
  }, [ordinary, main.data?.id, client, owner]);
  const activeRun = tasks.data?.find(run => run.sessionId === id && !isReadOnlyRun(run) && isActiveRun(run));
  const cancellingRun = tasks.data?.find(run => run.sessionId === id && !isReadOnlyRun(run) && isCancellationPending(run));
  const progressRun = activeRun ?? tasks.data?.find(run => run.sessionId === id && isReadOnlyRun(run));

  const refreshTerminalMessages = useCallback(async (runId: string, sessionId: string) => {
    if (runMessageStates.current.get(runId) === "refreshed") return;
    runMessageStates.current.set(runId, "refreshed");
    const queryKey = ["assistant-messages", owner, sessionId];
    // Discard an in-flight read which may predate the durable final reply.
    await client.cancelQueries({ queryKey, exact: true });
    await client.invalidateQueries({ queryKey, exact: true });
  }, [client, owner]);

  const requestRecovery = useRequestRecovery(
    owner,
    id,
    canUseSession && !pending[id],
    taskQueryKey,
    tasks.data,
    (run) => {
      const session = run.sessionId;
      if (!session || session !== id) return;
      const terminal = isTerminalRun(run);
      if (terminal) {
        void refreshTerminalMessages(run.id, session);
      } else {
        void client.invalidateQueries({ queryKey: ["assistant-messages", owner, session], exact: true });
      }
      if (isReadOnlyRun(run) || terminal) {
        if (runIds.current[session] && runIds.current[session] !== run.id) return;
        delete runIds.current[session];
        delete requests.current[session];
        setStopping(values => values[session] ? ({...values, [session]: false}) : values);
      } else runIds.current[session] = run.id;
    },
  );
  const knownRun = tasks.data?.find(run => run.sessionId === id && run.id === runIds.current[id]);
  const awaitingTerminal = Boolean(runIds.current[id] && (!knownRun || (!isReadOnlyRun(knownRun) && !isTerminalRun(knownRun))));
  const isStopping = Boolean(stopping[id] || requestRecovery.cancellation || cancellingRun);
  const backgroundKey = `${owner}:${id}`;
  const background =
    backgrounds[backgroundKey] ?? sessionBackground(current?.metadata);
  const setBackground = (selection: AssistantBackgroundSelection) =>
    setBackgrounds((values) => ({ ...values, [backgroundKey]: selection }));
  const messages = useQuery({
    queryKey: ["assistant-messages", owner, id],
    queryFn: () => readConversation(() => assistantApi.messages(id)),
    enabled: canUseSession,
    refetchInterval: tasks.data?.some(
      (run) => run.sessionId === id && isActiveRun(run),
    )
      ? 2500
      : false,
  });
  useEffect(() => {
    if (!tasks.isSuccess) return;
    let newestTerminal: WorkbenchAgentRun | undefined;
    for (const run of tasks.data) {
      if (!run.sessionId || isReadOnlyRun(run)) continue;
      if (isActiveRun(run) && !runMessageStates.current.has(run.id))
        runMessageStates.current.set(run.id, "active");
      if (!isTerminalRun(run)) continue;
      if (runMessageStates.current.get(run.id) === "active")
        void refreshTerminalMessages(run.id, run.sessionId);
      if (run.sessionId === id && (!newestTerminal ||
        (run.queuedAt ?? run.createdAt ?? "") > (newestTerminal.queuedAt ?? newestTerminal.createdAt ?? "")))
        newestTerminal = run;
    }
    if (!canUseSession || !newestTerminal || runMessageStates.current.has(newestTerminal.id)) return;
    const terminalId = newestTerminal.id;
    if (messages.data?.some((item) =>
      (item.role === "assistant" || isRunSystemReply(item)) && item.metadata?.agentRunId === terminalId,
    )) {
      runMessageStates.current.set(terminalId, "refreshed");
      return;
    }
    void refreshTerminalMessages(terminalId, id);
  }, [canUseSession, id, messages.data, refreshTerminalMessages, tasks.data, tasks.isSuccess]);

  const conversationDenied = detailUnavailable || messages.data === null;
  const composerLocked = !canUseSession || conversationDenied || Boolean(selectingCurrentProfile || profileUnconfirmed || tasks.isPending || tasks.isError || awaitingTerminal || isStopping || activeRun || pending[id] || requestRecovery.pending || requestRecovery.error || current?.activity || listedSession?.activity);

  const latestRun = tasks.data?.filter(run => run.sessionId === id).sort((a, b) => (b.queuedAt ?? "").localeCompare(a.queuedAt ?? ""))[0];
  const runsById = new Map((tasks.isError ? [] : tasks.data ?? []).map((run) => [run.id, run]));
  const renderRuntimeSummary = (item: WorkbenchMessage) => {
    if (item.role !== "assistant" && !isRunSystemReply(item)) return null;
    const runId = item.metadata?.agentRunId;
    const candidate = typeof runId === "string" ? runsById.get(runId) : undefined;
    const run = candidate?.sessionId === item.sessionId ? candidate : undefined;
    return (
      <AssistantRuntimeAssembly
        value={item.metadata?.runtimeAssembly}
        fallback={run?.runtimeAssembly}
        hookOutcomes={run?.output?.runtimeHooks ?? item.metadata?.runtimeHooks}
        toolExecutions={run?.toolExecutions}
      />
    );
  };
  const latestReply = messages.data?.filter(item => item.role !== "user").at(-1);
  const latestUser = messages.data?.filter(item => item.role === "user").at(-1);
  const latestMessage = messages.data?.at(-1);
  const durableMemoryDegraded = latestRun
    ? hasMemoryDegradation(latestRun) || (latestReply?.metadata?.agentRunId === latestRun.id && hasMemoryDegradation(latestReply)) || ((latestUser?.metadata?.agentRunId === latestRun.id || latestRun.input?.requestMessageId === latestUser?.id) && hasMemoryDegradation(latestUser))
    : hasMemoryDegradation(latestMessage) || (!latestMessage && hasMemoryDegradation(current));
  const memoryDegraded = memoryWarnings[id] === undefined
    ? durableMemoryDegraded
    : memoryWarnings[id] || hasMemoryDegradation(knownRun) || Boolean(knownRun && knownRun.id === latestRun?.id && durableMemoryDegraded);
  const side = useMutation({
    mutationFn: ordinary ? assistantApi.chatSide : assistantApi.side,
    onSuccess: (data) => {
      setSideOpen(false);
      setTitle("");
      openChat(data.id);
      void sessions.refetch();
    },
    onError: () => message.error("旁聊创建失败，请重试"),
  });
  const cancel = useMutation({
    mutationFn: async ({session, runId, requestId}: {session: string; runId: string; requestId?: string}) => {
      const target = tasks.data?.find(run => run.id === runId && run.sessionId === session);
      if (target && isReadOnlyRun(target))
        throw new Error("历史任务只读，请核对服务端状态");
      streams.current[session]?.abort();
      if (requestId) requestRecovery.markCancelling(session, requestId, runId);
      else requestRecovery.markRunCancelling(session, runId);
      setStopping(values => values[session] ? ({...values, [session]: false}) : values);
      const run = await assistantApi.cancel(runId);
      if (run?.id !== runId || run.sessionId !== session)
        throw new Error("停止回执与原任务不匹配");
      return run;
    },
    onSuccess: (run) => {
      requestRecovery.settleCancellation(run);
      if (isTerminalRun(run) && run.sessionId && runIds.current[run.sessionId] === run.id) {
        delete runIds.current[run.sessionId];
        delete requests.current[run.sessionId];
        setStopping(values => ({...values, [run.sessionId!]: false}));
      }
      const matchingTasks = {
        queryKey: ordinary ? ["assistant-tasks", owner, true, run.sessionId] : ["assistant-tasks", owner, false],
      };
      client.setQueriesData<WorkbenchAgentRun[]>(
        matchingTasks,
        (runs) => runs && [...runs.filter((item) => item.id !== run.id), run],
      );
      void client.invalidateQueries(matchingTasks);
      message.success(
        isTerminalRun(run) ? `任务状态：${statusNames[run.status]}` : "已请求取消，等待执行端确认",
      );
    },
    onError: () => message.error("任务取消失败，请检查最新状态"),
  });
  async function stop() {
    setStopping(values => ({...values, [id]: true}));
    streams.current[id]?.abort();
    const recovery = requestRecovery.cancellation;
    const local = requests.current[id];
    const requestId = recovery ? recovery.requestId : local?.recoverable ? local.id : undefined;
    let runId = recovery?.runId || (awaitingTerminal ? runIds.current[id] : undefined);
    if (!runId && !requestId) runId = cancellingRun?.id ?? activeRun?.id;
    try {
      if (!runId && requestId) {
        requestRecovery.markCancelling(id, requestId);
        setStopping(values => ({...values, [id]: false}));
        const run = await assistantApi.findRequest(id, requestId);
        if (isReadOnlyRun(run) || isTerminalRun(run)) {
          requestRecovery.markCancelling(id, requestId, run.id);
          requestRecovery.settleCancellation(run);
          delete requests.current[id];
          setStopping(values => ({...values, [id]: false}));
          return;
        }
        runId = run.id;
      }
      if (!runId) throw new Error("原任务尚未读取");
      runIds.current[id] = runId;
      await cancel.mutateAsync({session: id, runId, requestId});
    } catch {
      message.error("取消未确认，请重试停止；输入保持锁定。");
    }
  }
  useEffect(() => {
    const run = knownRun;
    if (!run || (!isTerminalRun(run) && !isReadOnlyRun(run))) return;
    delete runIds.current[id];
    if (stopping[id]) {
      delete requests.current[id];
      setStopping(values => ({...values, [id]: false}));
    }
  }, [knownRun, id, stopping]);
  useEffect(() => {
    if (!conversationDenied) return;
    streams.current[id]?.abort();
    setLive(values => values[id] ? ({...values, [id]: ""}) : values);
  }, [conversationDenied, id]);
  useEffect(
    () => () => {
      Object.values(streams.current).forEach((controller) =>
        controller.abort(),
      );
    },
    [],
  );
  useEffect(() => {
    bottom.current?.scrollIntoView?.({ block: "end" });
  }, [id, messages.data, live[id]]);
  function openChat(sessionId: string) {
    setParams({ session: sessionId });
    setSection("chat");
    setTopics(false);
  }
  async function attachImage(file: File) {
    if (!id || preparingImage || pending[id]) return;
    const target = id;
    setPreparingImage(true);
    try {
      if (appearanceDrafts[target]?.kind === "avatar") {
        const image = await prepareAssistantAvatar(file);
        setAppearanceDrafts((values) => ({
          ...values,
          [target]: { ...values[target], kind: "avatar", image },
        }));
        setDrafts((values) => ({
          ...values,
          [target]:
            values[target]?.trim() &&
            values[target]?.trim() !== "把虚拟形象改成"
              ? values[target]
              : "用这张图片作为你的头像",
        }));
      } else {
        const image = await prepareChatImage(file);
        setChatImages((values) => ({ ...values, [target]: [image] }));
      }
      composer.current?.focus();
    } catch (cause) {
      message.error(cause instanceof Error ? cause.message : "图片处理失败");
    } finally {
      setPreparingImage(false);
    }
  }
  async function send(
    content = drafts[id]?.trim(),
    taskIntent: WorkbenchTaskIntent = { capabilities: [] },
    appearance = appearanceDrafts[id],
  ): Promise<boolean> {
    if (!canUseSession || !id || !content || streams.current[id] || composerLocked) return false;
    if (ordinary && appearance) return false;
    const explicitTask = Boolean(taskIntent.capabilities?.length);
    const useDshForTurn = usesDsh || explicitTask;
    const input = {
      content,
      assistantTask: explicitTask ? undefined : appearance,
      mode: "general",
      ...(useDshForTurn ? { taskIntent, modelPreferences: background.modelPreferences ?? {} } : {}),
      knowledgeContext: {
        enabled: Boolean(background.knowledgeBaseIds?.length),
        knowledgeBaseIds: background.knowledgeBaseIds ?? [],
      },
      contextSelection: {
        memoryIds: background.memoryIds ?? [],
        images: chatImages[id],
      },
      agentProviderId: explicitTask ? "dsh" : undefined,
    };
    const selection = JSON.stringify(input);
    const controller = new AbortController();
    const request =
      requests.current[id]?.content === selection
        ? requests.current[id]
        : { content: selection, id: crypto.randomUUID(), recoverable: !appearance && useDshForTurn };
    requests.current[id] = request;
    if (request.recoverable) {
      try {
        requestRecovery.remember(id, request.id);
      } catch (error) {
        message.error(
          error instanceof Error ? error.message : "无法保存任务恢复标识",
        );
        return false;
      }
    }
    delete runIds.current[id];
    setMemoryWarnings(items => ({...items, [id]: false}));
    streams.current[id] = controller;
    setPending((items) => ({ ...items, [id]: true }));
    setChatImages((values) => ({ ...values, [id]: undefined }));
    if (!taskIntent.capabilities?.length)
      setDrafts((items) => ({ ...items, [id]: "" }));
    setLive((items) => ({ ...items, [id]: "" }));
    setStreamingRuntime((items) => ({ ...items, [id]: undefined }));
    let profileChanged = false;
    let appearanceFailed = false;
    let acceptanceSeen = false;
    try {
      await streamAssistant(
        id,
        { ...input, requestId: request.id },
        controller.signal,
        (event) => {
          if ("metadata" in event && event.metadata && typeof event.metadata === "object") {
            const metadata = event.metadata as Record<string, unknown>;
            if ("runtimeAssembly" in metadata || "runtimeHooks" in metadata)
              setStreamingRuntime((items) => ({
                ...items,
                [id]: {
                  assembly: metadata.runtimeAssembly ?? items[id]?.assembly,
                  hooks: metadata.runtimeHooks ?? items[id]?.hooks,
                },
              }));
          }
          if (hasMemoryDegradation(event)) setMemoryWarnings(items => ({...items, [id]: true}));
          acceptanceSeen = true;
          if (event.type === "agent.status" && event.runId) {
            if (event.providerKind !== "native") {
              runIds.current[id] = event.runId;
              if (!runMessageStates.current.has(event.runId))
                runMessageStates.current.set(event.runId, "active");
            }
            if (request.recoverable)
              requestRecovery.acknowledge(id, request.id, false, event.runId, event.providerKind === "native");
          }
          if (
            event.type === "tool.completed" &&
            ["assistant.rename", "assistant.avatar"].includes(
              event.toolCall.toolName,
            ) &&
            event.toolCall.status === "success"
          )
            profileChanged = true;
          if (
            event.type === "tool.completed" &&
            event.toolCall.toolName === "assistant.avatar" &&
            event.toolCall.status === "error"
          )
            appearanceFailed = true;
          if (event.type === "message.delta")
            setLive((items) => ({
              ...items,
              [id]: (items[id] || "") + event.contentDelta,
            }));
          if (event.type === "message.done")
            setLive((items) => ({ ...items, [id]: event.content }));
        },
      );
      if (!controller.signal.aborted) delete requests.current[id];
      if (appearance && !appearanceFailed)
        setAppearanceDrafts((values) => ({ ...values, [id]: undefined }));
      if (appearanceFailed)
        setDrafts((values) => ({ ...values, [id]: values[id] || content }));
      return !appearanceFailed;
    } catch (error) {
      if (!controller.signal.aborted && !acceptanceSeen && request.recoverable &&
          error instanceof ApiError &&
          (error.code === "request_not_accepted" || (error.status === 200 && error.code === "agent_unsupported")) &&
          requestRecovery.discardUnaccepted(id, request.id))
        delete requests.current[id];
      setChatImages((values) => ({
        ...values,
        [id]: values[id] || input.contextSelection.images,
      }));
      if (appearance && !profileChanged)
        setDrafts((items) => ({ ...items, [id]: items[id] || content }));
      if (
        !controller.signal.aborted &&
        owner === selectAssistantOwner(useAppStore.getState())
      ) {
        if (!taskIntent.capabilities?.length)
          setDrafts((items) => ({ ...items, [id]: items[id] || content }));
        message.error(
          error instanceof Error
            ? error.message
            : "回复未完成，请重新读取消息后重试",
        );
      }
      // Do not replay a POST automatically: its message/task may already be persisted.
      return false;
    } finally {
      delete streams.current[id];
      if (owner === selectAssistantOwner(useAppStore.getState())) {
        if (profileChanged) {
          setDrafts((values) => ({
            ...values,
            [id]: values[id] || heldDrafts[id] || "",
          }));
          setHeldDrafts((values) => ({ ...values, [id]: undefined }));
        }
        if (profileChanged || appearance)
          await client.invalidateQueries({
            queryKey: ["personal-assistant", owner],
          });
        setPending((items) => ({ ...items, [id]: false }));
        await client.invalidateQueries({
          queryKey: ["assistant-messages", owner, id],
        });
        if (!controller.signal.aborted) setLive((items) => ({ ...items, [id]: "" }));
        void tasks.refetch();
      }
    }
  }
  if (!canChat) return <Empty description="当前账号没有 AI 对话使用权限" />;
  if (!ordinary && !canUseAgent)
    return (
      <section className="app-assistant" aria-label="Heya 开通">
        <img src="/heya-avatar.svg" width={100} height={100} alt="Heya 嘿呀" />
        <Typography.Title level={2}>Heya · 嘿呀</Typography.Title>
        <Typography.Paragraph>
          {access.isError
            ? "开通状态读取失败"
            : access.isPending
              ? "正在读取开通状态…"
              : access.data?.status === "pending"
                ? "申请已提交，等待管理员批准。"
                : "开通个人 Agent 后，使用独立会话与个人执行环境。"}
        </Typography.Paragraph>
        {access.isError ? (
          <Button onClick={() => void access.refetch()}>重试</Button>
        ) : (
          <Button
            type="primary"
            loading={requestAccess.isPending}
            disabled={!access.data || access.data.status === "pending"}
            onClick={() => requestAccess.mutate()}
          >
            申请开通
          </Button>
        )}
      </section>
    );
  if (sessions.isError || (!ordinary && assistant.isError) || (ordinary && main.isError))
    return (
      <Empty description="个人会话读取失败">
        <Button
          onClick={() => {
            void sessions.refetch();
            if (ordinary) void main.refetch();
            else void assistant.refetch();
          }}
        >
          重试
        </Button>
      </Empty>
    );
  if (conversationDenied || (!needsDetail && !sessions.isPending && !current && (ordinary ? main.data : assistant.data)))
    return (
      <Empty description={ordinary ? "普通会话尚未读取或无权访问" : "这个会话不属于 Heya"}>
        {mainSessionId && id !== mainSessionId ? (
          <Button onClick={() => openChat(mainSessionId)}>返回主聊天</Button>
        ) : null}
        {detail.isError || messages.isError ? (
          <Button onClick={() => {
            if (detail.isError) void detail.refetch();
            else if (canUseSession) void messages.refetch();
          }}>
            重试
          </Button>
        ) : null}
      </Empty>
    );
  if (needsDetail && detail.isError && !current)
    return (
      <Empty description="会话读取失败">
        <Button onClick={() => void detail.refetch()}>重试</Button>
      </Empty>
    );
  const topicList = (
    <div className="app-assistant-topics">
      <Button
        type={id === mainSessionId ? "primary" : "text"}
        block
        onClick={() => mainSessionId && openChat(mainSessionId)}
        disabled={!mainSessionId}
      >
        主聊天
      </Button>
      <div className="app-assistant-topic-heading">
        <Typography.Text type="secondary">旁聊</Typography.Text>
        <Button
          aria-label="新增旁聊"
          type="text"
          icon={<PlusOutlined />}
          onClick={() => setSideOpen(true)}
        />
      </div>
      {[...(sessions.data ?? []), ...(!listedSession && current ? [current] : [])]
        .filter((item) => item.id !== mainSessionId)
        .map((item) => (
          <Button
            type="text"
            className={item.id === id ? "is-selected" : ""}
            block
            key={item.id}
            onClick={() => openChat(item.id)}
          >
            {item.title || "旁聊"}
          </Button>
        ))}
    </div>
  );
  const roots = tasks.data?.filter((run) => !run.parentRunId && (
    (canUseSession && run.sessionId === id) ||
    (!ordinary && sessions.data?.some(session => session.id === run.sessionId))
  )) ?? [];
  const canDeleteData = Boolean(
    assistant.data &&
    environment.data?.assistantId === assistant.data.id &&
    !environment.isError &&
    !environment.isFetching &&
    !environmentBusy &&
    environment.data.dataInitialized &&
    (environment.data.state === "sleeping" ||
      (environment.data.state === "deletion_unknown" &&
        deletionReconciled ===
          `${environment.data.assistantId}:${environment.data.version}`)),
  );
  const deletionMatches = Boolean(
    canDeleteData &&
    deletionTarget &&
    deletionTarget.id === assistant.data?.id &&
    deletionTarget.name === assistant.data?.name &&
    deletionTarget.version === environment.data?.version &&
    deletionName === deletionTarget.name,
  );
  return (
    <section className="app-assistant" aria-label="个人 AI 助手">
      <header className="app-assistant-header">
        <Button
          className="app-assistant-topic-toggle"
          aria-label="切换话题"
          type="text"
          icon={<MenuUnfoldOutlined />}
          onClick={() => setTopics(true)}
        />
        <img src="/heya-avatar.svg" alt="" />
        <div>
          <Typography.Text strong>
            {ordinary ? "Chat" : assistant.data?.name || "heya"}
          </Typography.Text>
          <Typography.Text type="secondary">
            {id === mainSessionId
              ? "主聊天"
              : current?.title || "准备中"}
          </Typography.Text>
        </div>
        <Tag>{ordinary ? "Chat" : "个人助手"}</Tag>
      </header>
      <Segmented
        className="app-assistant-sections"
        value={section}
        options={ordinary ? sections.filter(item => ["chat", "tasks"].includes(item.value)) : sections}
        onChange={(value) => setSection(value as Section)}
      />
      {requestRecovery.pending && !pending[id] ? (
        <Alert
          type="warning"
          title="任务提交结果未确认"
          description="正在读取原任务。关闭页面不会停止已经接收的任务。"
          action={<Button onClick={requestRecovery.recheck}>重新读取</Button>}
        />
      ) : null}
      {memoryDegraded ? <Alert type="warning" title="长期记忆暂不可用，本次对话将继续" description="本次无法读取或自动保存的长期记忆不会作为已成功使用或保存；可以继续对话，稍后查看个人记忆状态。" /> : null}
      {needsDetail && detail.isError ? (
        <Alert type="error" title="会话读取失败" action={<Button onClick={() => void detail.refetch()}>重新读取会话</Button>} />
      ) : null}
      {tasks.isError ? <Alert type="error" title="任务状态读取失败，暂不能发送新消息" action={<Button onClick={() => void tasks.refetch()}>重新读取任务</Button>} /> : null}
      {requestRecovery.error ? (
        <Alert type="error" title={requestRecovery.error} />
      ) : null}
      {isStopping ? <Alert type="warning" title="取消处理中，等待服务端终态" description="已停止接收；部分结果保留，副作用尚未确认。" action={<Button disabled={cancel.isPending} onClick={() => void stop()}>重试停止</Button>} /> : null}
      <div className={`app-assistant-workspace is-${section}`}>
        {section === "chat" ? (
          <>
            <aside>{topicList}</aside>
            <div className="app-assistant-chat">
              <div className="app-assistant-messages" aria-live="polite">
                {messages.isPending || (ordinary ? main.isPending : assistant.isPending) ? <Spin /> : null}
                {messages.isError ? (
                  <Alert
                    type="error"
                    title="消息读取失败"
                    action={
                      <Button onClick={() => void messages.refetch()}>
                        重试
                      </Button>
                    }
                  />
                ) : null}
                {!messages.isPending &&
                !messages.isError &&
                !messages.data?.length ? (
                  <Empty description="在主聊天保持联系，用旁聊整理独立话题。" />
                ) : null}
                {messages.data?.map((item) => (
                  <div
                    key={item.id}
                    className={`app-assistant-message is-${item.role}`}
                  >
                    <Typography.Text type="secondary">
                      {item.role === "assistant" && (
                        <AssistantAvatar assistant={assistant.data} />
                      )}
                      {item.role === "user"
                        ? "你"
                        : ordinary ? "Chat" : assistant.data?.name || "heya"}
                    </Typography.Text>
                    <div className="app-assistant-message-content">
                      {item.role === "user" &&
                        messageImages(item).map((image) => (
                          <Image
                            key={image.id}
                            src={image.dataUrl}
                            alt={image.name}
                            className="app-assistant-chat-image"
                          />
                        ))}
                      <div>{item.content}</div>
                      {item.role === "user" &&
                        messageReaction(messages.data || [], item) && (
                          <span
                            className="app-assistant-message-reaction"
                            role="img"
                            aria-label={`助手回应 ${messageReaction(messages.data || [], item)}`}
                          >
                            {messageReaction(messages.data || [], item)}
                          </span>
                        )}
                    </div>
                    <MessageBackground item={item} />
                    {renderRuntimeSummary(item)}
                    {!isRunSystemReply(item) && (
                      <>
                        <Button
                          size="small"
                          type="text"
                          onClick={() =>
                            setDrafts((values) => ({
                              ...values,
                              [id]: `引用：${item.content.slice(0, 2000)}\n\n${values[id] || ""}`,
                            }))
                          }
                        >
                          引用回复
                        </Button>
                        <AssistantAppearanceResult
                          metadata={item.metadata}
                          busy={pending[id]}
                          onContinue={() => {
                            setDrafts((values) => ({
                              ...values,
                              [id]: values[id]
                                ? `${values[id]}\n调整你的头像：`
                                : "调整你的头像：",
                            }));
                            setAppearanceDrafts((values) => ({
                              ...values,
                              [id]: { kind: "avatar", useCurrentAvatar: true },
                            }));
                            composer.current?.focus({ cursor: "end" });
                          }}
                          onUndo={() =>
                            void send(
                              "撤销这次形象更改",
                              { capabilities: [] },
                              { kind: "undo", messageId: item.id },
                            )
                          }
                        />
                        <MessageApprovals item={item} readOnly={tasks.data?.some(run => run.id === item.metadata?.agentRunId && isReadOnlyRun(run))} />
                        {bootstrap?.permissionSnapshot.permissionKeys.includes(
                          "ai.memory.update",
                        ) &&
                        bootstrap.permissionSnapshot.permissionKeys.includes(
                          "ai.memory.view",
                        ) ? (
                          <Button
                            size="small"
                            type="text"
                            onClick={() =>
                              setMemoryDraft({
                                fact: item.content,
                                refs: [
                                  `soha://session/${encodeURIComponent(item.sessionId)}/message/${encodeURIComponent(item.id)}`,
                                ],
                              })
                            }
                          >
                            保存为个人记忆
                          </Button>
                        ) : null}
                      </>
                    )}
                  </div>
                ))}
                {pending[id] || live[id] ? (
                  <div className="app-assistant-message">
                    <Typography.Text type="secondary">
                      {ordinary ? "Chat" : assistant.data?.name || "heya"}
                    </Typography.Text>
                    <div>{live[id] || "正在回复…"}</div>
                    <AssistantRuntimeAssembly
                      value={streamingRuntime[id]?.assembly}
                      fallback={!tasks.isError ? knownRun?.runtimeAssembly : undefined}
                      hookOutcomes={(!tasks.isError ? knownRun?.output?.runtimeHooks : undefined) ?? streamingRuntime[id]?.hooks}
                      toolExecutions={!tasks.isError ? knownRun?.toolExecutions : undefined}
                    />
                  </div>
                ) : null}
                {!pending[id] && !tasks.isError && latestRun && !messages.data?.some(
                  (item) => item.role !== "user" && item.metadata?.agentRunId === latestRun.id,
                ) && (
                  <AssistantRuntimeAssembly value={latestRun.runtimeAssembly} hookOutcomes={latestRun.output?.runtimeHooks} toolExecutions={latestRun.toolExecutions} />
                )}
                {progressRun && isDurableRun(progressRun) ? <RunTaskProgress key={progressRun.id} run={progressRun} /> : null}
                <div ref={bottom} />
              </div>
              <div
                className="app-assistant-composer"
                onDragOver={(event) => {
                  event.preventDefault();
                }}
                onDrop={(event) => {
                  event.preventDefault();
                  if (event.dataTransfer.files[0])
                    void attachImage(event.dataTransfer.files[0]);
                }}
              >
                <input
                  hidden
                  type="file"
                  ref={imagePicker}
                  aria-label="添加形象图片"
                  accept="image/png,image/jpeg,image/gif,image/webp"
                  onChange={(event) => {
                    const file = event.target.files?.[0];
                    event.target.value = "";
                    if (file) void attachImage(file);
                  }}
                />
                {Boolean(heldDrafts[id]) && (
                  <div className="app-assistant-chat-task">
                    <span>原草稿已保留</span>
                    <Button
                      type="text"
                      disabled={pending[id]}
                      onClick={() => {
                        setDrafts((values) => ({
                          ...values,
                          [id]: heldDrafts[id] || "",
                        }));
                        setHeldDrafts((values) => ({
                          ...values,
                          [id]: undefined,
                        }));
                        setAppearanceDrafts((values) => ({
                          ...values,
                          [id]: undefined,
                        }));
                      }}
                    >
                      返回原草稿
                    </Button>
                  </div>
                )}
                {appearanceDrafts[id] && (
                  <div className="app-assistant-chat-task">
                    {appearanceDrafts[id]?.image && (
                      <img
                        src={appearanceDrafts[id]?.image?.avatarPosterUrl}
                        alt="待发送的形象图片"
                      />
                    )}
                    <span>
                      {appearanceDrafts[id]?.image
                        ? "形象参考图"
                        : "调整助手形象"}
                    </span>
                    <Button
                      type="text"
                      aria-label="退出形象调整"
                      disabled={pending[id]}
                      onClick={() =>
                        setAppearanceDrafts((values) => ({
                          ...values,
                          [id]: undefined,
                        }))
                      }
                    >
                      ×
                    </Button>
                  </div>
                )}
                {chatImages[id]?.map((image) => (
                  <div
                    key={image.id}
                    className="app-assistant-chat-task is-chat-image"
                  >
                    <img src={image.dataUrl} alt={image.name} />
                    <span>{image.name}</span>
                    <Button
                      type="text"
                      aria-label={`移除图片 ${image.name}`}
                      disabled={pending[id]}
                      onClick={() =>
                        setChatImages((values) => ({
                          ...values,
                          [id]: undefined,
                        }))
                      }
                    >
                      ×
                    </Button>
                  </div>
                ))}
                {Boolean(
                  background.memoryIds?.length ||
                  background.knowledgeBaseIds?.length,
                ) && (
                  <div className="app-assistant-context-chips">
                    {background.memoryIds?.length ? (
                      <Tag>记忆 · {background.memoryIds.length}</Tag>
                    ) : null}
                    {background.knowledgeBaseIds?.length ? (
                      <Tag>知识库 · {background.knowledgeBaseIds.length}</Tag>
                    ) : null}
                  </div>
                )}
                {usesDsh && canUseSession && !conversationDenied && (
                  <Space orientation="vertical" size={4}>
                    <AssistantRuntimeProfileControl
                      scope={scope}
                      profileId={profileId}
                      profiles={runtimeProfiles.isSuccess ? runtimeProfiles.data : undefined}
                      selected={runtimeProfile}
                      disabled={composerLocked || selectProfile.isPending || !runtimeProfiles.isSuccess || Boolean(current?.metadata?.archivedAt)}
                      loading={runtimeProfiles.isPending || selectingCurrentProfile || profileCheck?.status === "checking"}
                      onChange={(profileId) => selectProfile.mutate({ sessionId: id, profileId })}
                      onManage={canOpenProfileSettings ? openProfileSettings : undefined}
                    />
                    {runtimeProfiles.isError && (
                      <Button size="small" onClick={() => void runtimeProfiles.refetch()}>
                        运行配置读取失败，重试
                      </Button>
                    )}
                    {profileCheck?.status === "checking" && (
                      <Typography.Text type="secondary">正在读取服务端运行配置…</Typography.Text>
                    )}
                    {profileCheck?.status === "unavailable" && (
                      <Alert type="warning" title="运行配置保存未确认，读取会话失败。确认前暂停发送。" action={
                        <Button size="small" onClick={() => void checkRuntimeProfile(id, profileCheck.requested)}>重试读取会话</Button>
                      } />
                    )}
                    {profileCheck?.status === "observed" && (
                      <Alert type="warning" title="已读取服务端运行配置，所选配置未生效。" />
                    )}
                    {profileCheck?.status === "saved" && profileId === profileCheck.requested && (
                      <Typography.Text type="secondary">运行配置已保存，下一轮生效。</Typography.Text>
                    )}
                  </Space>
                )}
                <div className="app-assistant-composer-row">
                  <Popover
                    fresh
                    trigger="click"
                    placement="topLeft"
                    arrow={false}
                    open={addOpen && !pending[id]}
                    onOpenChange={setAddOpen}
                    content={
                      <div
                        className="app-assistant-add-menu"
                        onKeyDown={(event) => {
                          if (event.key === "Escape") {
                            setAddOpen(false);
                            composer.current?.focus();
                          }
                        }}
                      >
                        <Button
                          type="text"
                          icon={<PictureOutlined />}
                          aria-label="添加图片"
                          disabled={!id || pending[id] || preparingImage}
                          onClick={() => {
                            imagePicker.current?.click();
                            setAddOpen(false);
                          }}
                        >
                          添加图片
                        </Button>
                        <AssistantBackground
                          mode={ordinary ? "chat" : "heya"}
                          key={backgroundKey}
                          selection={background}
                          onChange={setBackground}
                        />
                        <Button
                          type="text"
                          icon={<ExperimentOutlined aria-hidden />}
                          disabled={!id || composerLocked}
                          onClick={() => {
                            setAddOpen(false);
                            setProfessionalOpen(true);
                          }}
                        >
                          专业分析任务
                        </Button>
                        <Popover
                          trigger="click"
                          content={
                            <Space>
                              {["👍", "❤️", "🎉", "🤔", "😊"].map((emoji) => (
                                <Button
                                  type="text"
                                  key={emoji}
                                  onClick={() => {
                                    setDrafts((values) => ({
                                      ...values,
                                      [id]: `${values[id] || ""}${emoji}`,
                                    }));
                                    setAddOpen(false);
                                  }}
                                >
                                  {emoji}
                                </Button>
                              ))}
                            </Space>
                          }
                        >
                          <Button type="text" icon={<SmileOutlined />}>
                            表情
                          </Button>
                        </Popover>
                      </div>
                    }
                  >
                    <Button
                      type="text"
                      shape="circle"
                      aria-label="添加内容"
                      aria-expanded={addOpen}
                      icon={<PlusOutlined />}
                      loading={preparingImage}
                      disabled={!id || pending[id]}
                    />
                  </Popover>
                  <Input.TextArea
                    ref={composer}
                    disabled={preparingImage || composerLocked}
                    onPaste={(event) => {
                      if (event.clipboardData.files[0]) {
                        event.preventDefault();
                        void attachImage(event.clipboardData.files[0]);
                      }
                    }}
                    aria-label="给助手发消息"
                    placeholder="消息"
                    autoSize={{ minRows: 1, maxRows: 6 }}
                    value={drafts[id] || ""}
                    maxLength={16384}
                    onChange={(event) =>
                      setDrafts((values) => ({
                        ...values,
                        [id]: event.target.value,
                      }))
                    }
                    onKeyDown={(event) => {
                      if (
                        event.key === "Enter" &&
                        !event.shiftKey &&
                        !event.nativeEvent.isComposing
                      ) {
                        event.preventDefault();
                        void send();
                      }
                    }}
                  />
                  <AssistantContextUsage
                    item={[...(messages.data ?? [])]
                      .reverse()
                      .find((item) => item.role !== "user")}
                  />
                  {usesDsh && (
                    <AssistantModel
                      selection={background}
                      profilePreferences={runtimeProfile?.modelPreferences}
                      onChange={setBackground}
                      disabled={composerLocked || preparingImage}
                    />
                  )}
                  {pending[id] || activeRun || awaitingTerminal || isStopping ? (
                    <Button
                      shape="circle"
                      aria-label="停止接收"
                      disabled={cancel.isPending}
                      title={isStopping ? "取消未确认，重试停止" : "停止并取消任务"}
                      icon={<StopOutlined />}
                      onClick={() => void stop()}
                    />
                  ) : (
                    <Button
                      type="primary"
                      shape="circle"
                      aria-label="发送"
                      icon={<ArrowUpOutlined />}
                      disabled={!id || !drafts[id]?.trim() || composerLocked}
                      onClick={() => void send()}
                    ></Button>
                  )}
                </div>
              </div>
            </div>
          </>
        ) : null}
        {section === "tasks" ? (
          <div className="app-assistant-content">
            <Typography.Title level={4}>你的后台任务</Typography.Title>
            <Typography.Paragraph type="secondary">
              任务状态由服务端保存，各个话题集中在这里。
            </Typography.Paragraph>
            {tasks.isError ? (
              <Button onClick={() => void tasks.refetch()}>
                任务读取失败，重试
              </Button>
            ) : tasks.isPending ? (
              <Spin />
            ) : !roots.length ? (
              <Empty description="还没有后台任务" />
            ) : (
              roots.map((run) => (
                <article key={run.id} className="app-assistant-task">
                  <Typography.Text strong>
                    {typeof run.input?.question === "string"
                      ? run.input.question
                      : `${run.providerKind} 任务`}
                  </Typography.Text>
                  <Tag>{isCancellationPending(run) ? "取消处理中" : statusNames[run.status] || run.status}</Tag>
                  <TaskUsage value={run.output?.usage} />
                  <AssistantRuntimeAssembly value={run.runtimeAssembly} hookOutcomes={run.output?.runtimeHooks} toolExecutions={run.toolExecutions} />
                  {isDurableRun(run) ? (
                    <RunTaskProgress key={`${owner}:${run.id}`} run={run} />
                  ) : null}
                  {run.errorMessage ? (
                    <Alert type="error" title={run.errorMessage} />
                  ) : null}
                  <Space>
                    {run.sessionId ? (
                      <Button onClick={() => openChat(run.sessionId!)}>
                        打开对话
                      </Button>
                    ) : null}
                    {run.sessionId && !isReadOnlyRun(run) && isActiveRun(run) ? (
                      <Button
                        loading={
                          cancel.isPending && cancel.variables?.runId === run.id
                        }
                        disabled={cancel.isPending}
                        onClick={() => cancel.mutate({session: run.sessionId!, runId: run.id})}
                      >
                        {isCancellationPending(run) ? "重试停止" : "取消任务"}
                      </Button>
                    ) : null}
                  </Space>
                  <TaskApprovals
                    run={run}
                    messages={run.sessionId === id ? (messages.data ?? []) : []}
                  />
                </article>
              ))
            )}
          </div>
        ) : null}
        {section === "results" ? (
          <div className="app-assistant-content">
            <Typography.Title level={4}>你的成果</Typography.Title>
            {artifacts.isError ? (
              <Button onClick={() => void artifacts.refetch()}>
                成果读取失败，重试
              </Button>
            ) : artifacts.isPending ? (
              <Spin />
            ) : !artifacts.data?.length ? (
              <Empty description="暂时没有成果" />
            ) : (
              artifacts.data.map((entry) => (
                <article key={entry.id} className="app-assistant-task">
                  <Typography.Text strong>
                    {entry.artifact.title || entry.artifact.kind}
                  </Typography.Text>
                  <Typography.Paragraph>
                    {entry.artifact.summary}
                  </Typography.Paragraph>
                  <Space>
                    <Button onClick={() => setResult(entry.artifact)}>
                      查看成果
                    </Button>
                    {entry.sessionId ? (
                      <Button onClick={() => openChat(entry.sessionId!)}>
                        打开对话
                      </Button>
                    ) : null}
                  </Space>
                </article>
              ))
            )}
          </div>
        ) : null}
        {section === "me" ? (
          <div className="app-assistant-content">
            {assistant.data && (
              <AssistantProfile
                assistant={assistant.data}
                busy={Object.values(pending).some(Boolean)}
                onPrompt={(kind) => {
                  const prefix =
                    kind === "name" ? "把你的名称改为 " : "把虚拟形象改成 ";
                  setHeldDrafts((values) => ({
                    ...values,
                    [id]: values[id] ?? drafts[id] ?? "",
                  }));
                  setDrafts((values) => ({ ...values, [id]: prefix }));
                  setAppearanceDrafts((values) => ({
                    ...values,
                    [id]: kind === "avatar" ? { kind: "avatar" } : undefined,
                  }));
                  setSection("chat");
                  requestAnimationFrame(() =>
                    composer.current?.focus({ cursor: "end" }),
                  );
                }}
              />
            )}
            <Typography.Paragraph>
              主聊天与旁聊共享助手身份，各自保留消息和背景。
            </Typography.Paragraph>
            <Alert
              type="info"
              title={`个人工作空间：${environment.isError ? "读取失败" : environment.isPending ? "正在读取…" : environment.data ? (personalVMPending ? "VM 待就绪" : environmentNames[environment.data.state] || "状态未确认") : "尚未读取"}`}
              description={
                environment.isPending
                  ? "正在读取个人环境的最近回执。"
                  : environment.isError
                    ? "无法确认环境状态，请重新读取。"
                    : environment.data?.state === "unprovisioned"
                      ? "个人工作空间尚未开通。后台任务由已配置的运行器执行。"
                      : environment.data?.state === "deleted"
                        ? "持久数据已删除，已保留防重建记录。"
                        : ["deleting", "deletion_unknown"].includes(
                              environment.data?.state || "",
                            )
                          ? "持久数据删除尚未确认，请先核对环境。不会自动重试删除。"
                          : environment.data?.state === "unknown"
                            ? "上次操作结果未确认，需核对原租约后再恢复。"
                            : personalVMPending
                              ? "VM 已绑定，等待初始化与就绪验证。就绪前个人环境操作不可用，聊天仍可继续。"
                              : "环境状态来自服务端最近的实际回执。休眠保留持久数据。"
              }
            />
            {owner && !environment.isError && environment.data?.backend === "vm" && environment.data.dataInitialized && environment.data.assistantId === assistant.data?.id ? <PersonalVMWorkspace key={`${owner}:${environment.data.assistantId}`} owner={owner} environment={environment.data} onRefresh={() => void environment.refetch()} /> : null}
            {environment.data?.dataInitialized &&
            environment.data.state !== "deleted" ? (
              <Typography.Paragraph type="secondary">
                持久文件保留至你显式删除。休眠、到期和取消不会删除文件；休眠后可导出
                TAR 归档，最大 256 MiB。
              </Typography.Paragraph>
            ) : null}
            {environmentExport.isPending ? (
              <Button onClick={() => environmentExportAbort.current?.abort()}>
                取消导出
              </Button>
            ) : null}
            {!environment.isError && environment.data?.observedAt ? (
              <Typography.Paragraph>
                环境观察时间：
                {new Date(environment.data.observedAt).toLocaleString()}
              </Typography.Paragraph>
            ) : null}
            <Button
              className="app-assistant-environment-refresh"
              loading={environment.isFetching}
              onClick={() => void environment.refetch()}
            >
              刷新环境状态
            </Button>
            {!environment.isError &&
            !environment.isPending &&
            environment.data ? (
              <div className="app-assistant-environment-controls">
                {environment.data.state === "unprovisioned" ? (
                  <>
                    <Select
                      aria-label="个人环境模板"
                      placeholder="选择个人环境模板"
                      value={selectedEnvironmentTemplate?.id}
                      loading={environmentTemplates.isFetching}
                      disabled={environmentBusy || environmentTemplates.isError}
                      options={
                        environmentTemplates.data?.map((item) => ({
                          value: item.id,
                          label: `${item.name}（${item.backend === "vm" ? `VM · ${item.provider?.toUpperCase() || "提供方未确认"}` : "Docker"}）`,
                        })) ?? []
                      }
                      onChange={setEnvironmentTemplate}
                    />
                    <Typography.Text type="secondary">
                      {environmentTemplates.isError
                        ? "模板读取失败，请重新读取。"
                        : environmentTemplates.isFetching
                          ? "正在读取可用模板…"
                          : !environmentTemplates.data?.length
                            ? "暂无获准的个人环境模板，请联系管理员配置。"
                            : "模板是配置，开通后仍需节点回执确认。"}
                    </Typography.Text>
                    {selectedEnvironmentTemplate ? (
                      <Typography.Text type="secondary">
                        {selectedEnvironmentTemplate.mode === "observe-only"
                          ? "持久数据只读"
                          : "持久数据可写"}{" "}
                        · 磁盘{" "}
                        {Math.round(
                          selectedEnvironmentTemplate.quota.diskBytes / 1048576,
                        )}{" "}
                        MiB · 内存{" "}
                        {Math.round(
                          selectedEnvironmentTemplate.quota.memoryBytes /
                            1048576,
                        )}{" "}
                        MiB · 租约 {selectedEnvironmentTemplate.leaseSeconds} 秒
                      </Typography.Text>
                    ) : null}
                    {environmentTemplates.isError ? (
                      <Button
                        onClick={() => void environmentTemplates.refetch()}
                      >
                        重新读取模板
                      </Button>
                    ) : null}
                    <Button
                      loading={environmentBusy}
                      disabled={
                        !selectedEnvironmentTemplate ||
                        environmentTemplates.isError ||
                        environmentTemplates.isFetching
                      }
                      onClick={() =>
                        environmentChange.mutate({
                          action: "wake",
                          templateId: selectedEnvironmentTemplate!.id,
                        })
                      }
                    >
                      开通个人环境
                    </Button>
                  </>
                ) : !["pending", "deleting", "deleted"].includes(
                    environment.data.state,
                  ) ? (
                  <Space wrap>
                    {environment.data.state === "sleeping" &&
                    environment.data.dataInitialized ? (
                      <Button
                        disabled={
                          !canExportData ||
                          environmentBusy ||
                          environment.isFetching ||
                          environment.isError ||
                          environment.data.assistantId !== assistant.data?.id
                        }
                        loading={environmentExport.isPending}
                        aria-label="导出持久文件"
                        onClick={() =>
                          environmentExport.mutate({
                            assistantId: environment.data!.assistantId,
                            environmentVersion: environment.data!.version,
                          })
                        }
                      >
                        导出持久文件
                      </Button>
                    ) : null}
                    {environment.data.state === "sleeping" &&
                    environment.data.dataInitialized &&
                    !canExportData ? (
                      <Typography.Text type="secondary">
                        当前设备暂不支持文件导出，请使用桌面端或 Web。
                      </Typography.Text>
                    ) : null}
                    {["ready", "quota_exceeded"].includes(
                      environment.data.state,
                    ) ? (
                      <Button
                        loading={environmentBusy}
                        onClick={() =>
                          environmentChange.mutate({ action: "sleep" })
                        }
                      >
                        休眠环境
                      </Button>
                    ) : null}
                    {["sleeping", "expired", "missing"].includes(
                      environment.data.state,
                    ) ? (
                      <Button
                        loading={environmentBusy}
                        onClick={() =>
                          environmentChange.mutate({ action: "wake" })
                        }
                      >
                        {environment.data.state === "missing"
                          ? "恢复环境"
                          : "唤醒环境"}
                      </Button>
                    ) : null}
                    <Button
                      disabled={environmentBusy}
                      onClick={() =>
                        environmentChange.mutate({ action: "reconcile" })
                      }
                    >
                      核对环境
                    </Button>
                    {["sleeping", "deletion_unknown"].includes(
                      environment.data.state,
                    ) ? (
                      <Button
                        danger
                        disabled={!canDeleteData}
                        onClick={() => {
                          if (
                            !canDeleteData ||
                            !assistant.data ||
                            !environment.data
                          )
                            return;
                          setDeletionName("");
                          setDeletionTarget({
                            id: assistant.data.id,
                            name: assistant.data.name,
                            version: environment.data.version,
                          });
                        }}
                      >
                        删除持久数据
                      </Button>
                    ) : null}
                  </Space>
                ) : null}
                {environment.data.state === "missing" ? (
                  <Typography.Text type="secondary">
                    恢复需要已有持久卷，不会重新创建空数据。
                  </Typography.Text>
                ) : null}
              </div>
            ) : null}
            <Modal
              title="删除个人持久数据"
              open={Boolean(deletionTarget)}
              okText="确认删除数据"
              cancelText="取消"
              confirmLoading={environmentDeletion.isPending}
              okButtonProps={{
                danger: true,
                disabled: !deletionMatches,
                "aria-label": "确认删除数据",
              }}
              onCancel={() => {
                if (environmentDeletion.isPending) return;
                setDeletionTarget(undefined);
                setDeletionName("");
              }}
              onOk={async () => {
                if (!deletionMatches || !deletionTarget) return;
                try {
                  await environmentDeletion.mutateAsync({
                    assistantId: deletionTarget.id,
                    environmentVersion: deletionTarget.version,
                    confirmationName: deletionName,
                  });
                  setDeletionTarget(undefined);
                  setDeletionName("");
                } catch {
                  // Keep the selection visible; a refreshed receipt gates another explicit request.
                }
              }}
            >
              <p>
                将永久删除「{deletionTarget?.name}
                」的持久文件。请先自行保留所需文件。
              </p>
              <p>
                输入助手完整名称「{deletionTarget?.name}
                」确认；取消不会发送删除请求。
              </p>
              <Input
                aria-label="确认删除数据的助手全名"
                value={deletionName}
                maxLength={60}
                disabled={environmentBusy}
                onChange={(event) => setDeletionName(event.target.value)}
              />
              {deletionTarget && !canDeleteData ? (
                <p role="status">环境或助手资料已变化，请取消并重新核对。</p>
              ) : null}
            </Modal>
            <details>
              <summary>连接详情</summary>
              <Typography.Paragraph code>
                助手：{assistant.data?.id}
              </Typography.Paragraph>
              <Typography.Paragraph code>
                主聊天：{mainSessionId}
              </Typography.Paragraph>
            </details>
          </div>
        ) : null}
      </div>
      <nav className="app-assistant-bottom" aria-label="个人助手导航">
        {sections.map((item) => (
          <Button
            type="text"
            key={item.value}
            aria-label={item.label}
            aria-current={section === item.value ? "page" : undefined}
            icon={item.icon}
            onClick={() => setSection(item.value as Section)}
          >
            {item.label}
          </Button>
        ))}
      </nav>
      <Drawer
        title="对话与旁聊"
        placement="left"
        open={topics}
        onClose={() => setTopics(false)}
        size="min(320px, 100vw)"
      >
        {topicList}
      </Drawer>
      {professionalOpen ? (
        <ProfessionalTask
          key={`${owner}:${id}`}
          onClose={() => setProfessionalOpen(false)}
          onSubmit={send}
          pending={Boolean(pending[id])}
          toolset={current?.metadata?.toolset}
        />
      ) : null}
      {memoryDraft ? (
        <MemoryEditor
          mode={ordinary ? "chat" : "heya"}
          key={backgroundKey}
          initial={memoryDraft}
          selection={background.memoryIds ?? []}
          onChange={(memoryIds) => setBackground({ ...background, memoryIds })}
          onClose={() => setMemoryDraft(undefined)}
        />
      ) : null}
      <Modal
        title="新增旁聊"
        open={sideOpen}
        onCancel={() => setSideOpen(false)}
        confirmLoading={side.isPending}
        okButtonProps={{ disabled: !title.trim() }}
        onOk={() => side.mutate(title.trim())}
      >
        <Input
          aria-label="旁聊名称"
          placeholder="为这个独立话题起个名字"
          maxLength={80}
          value={title}
          onChange={(event) => setTitle(event.target.value)}
          onPressEnter={() =>
            title.trim() && !side.isPending && side.mutate(title.trim())
          }
        />
      </Modal>
      <Drawer
        title={result?.title || "成果"}
        open={Boolean(result)}
        onClose={() => setResult(undefined)}
        size="min(640px, 100vw)"
      >
        {result ? (
          <>
            <Typography.Paragraph>{result.summary}</Typography.Paragraph>
            <pre className="app-assistant-result">
              {typeof result.dataSourceSnapshot?.content === "string"
                ? result.dataSourceSnapshot.content
                : JSON.stringify(
                    {
                      evidence: result.evidence,
                      hypotheses: result.hypotheses,
                      recommendations: result.recommendations,
                    },
                    null,
                    2,
                  )}
            </pre>
          </>
        ) : null}
      </Drawer>
    </section>
  );
}

function TaskApprovals({
  run,
}: {
  run: WorkbenchAgentRun;
  messages?: WorkbenchMessage[];
}) {
  const ids = new Set<string>();
  for (const tool of run.toolExecutions ?? []) {
    const id = approvalId(tool);
    if (id) ids.add(id);
  }
  if (
    isDurableRun(run) &&
    Array.isArray(run.output?.approvalRequestIds)
  ) {
    for (const id of run.output.approvalRequestIds.slice(0, 8)) {
      if (typeof id === "string" && id.length > 0) ids.add(id);
    }
  }
  return (
    <>
      {[...ids].map((id) => (
        <AssistantApproval
          key={id}
          id={id}
          continuesTask={isDurableRun(run) && !isReadOnlyRun(run)}
          readOnly={isReadOnlyRun(run)}
        />
      ))}
    </>
  );
}

function approvalId(tool: {
  toolName: string;
  output?: Record<string, unknown>;
}) {
  const related = tool.output?.relatedIds as
    Record<string, unknown> | undefined;
  const id = related?.approvalRequestId ?? related?.confirmationRequestId;
  return tool.toolName === "change.request" && typeof id === "string"
    ? id
    : undefined;
}

function MessageApprovals({ item, readOnly }: { item: WorkbenchMessage; readOnly?: boolean }) {
  const metadata = item.metadata;
  const agentStatus = metadata?.agentStatus;
  const providerKind = agentStatus && typeof agentStatus === "object" && "providerKind" in agentStatus
    ? agentStatus.providerKind
    : undefined;
  const historical = readOnly || metadata?.executionReadOnly === true ||
    metadata?.agentStopReason === "legacy_reconciliation_required" ||
    metadata?.agentProviderId === "native" ||
    (typeof providerKind === "string" && providerKind.trim().toLowerCase() === "native");
  const tools = metadata?.toolExecutions;
  const ids = Array.isArray(tools)
    ? tools.map(approvalId).filter((id): id is string => Boolean(id))
    : [];
  return (
    <>
      {[...new Set(ids)].map((id) => (
        <AssistantApproval key={id} id={id} readOnly={historical} />
      ))}
    </>
  );
}

function AssistantApproval({
  id,
  continuesTask = false,
  readOnly = false,
}: {
  id: string;
  continuesTask?: boolean;
  readOnly?: boolean;
}) {
  const { message, modal } = App.useApp();
  const confirmation = useRef<ReturnType<typeof modal.confirm> | null>(null);
  useEffect(() => () => confirmation.current?.destroy(), [readOnly]);
  const owner = useAppStore(selectAssistantOwner);
  const permissions = useAppStore(
    (state) => state.bootstrap?.permissionSnapshot.permissionKeys ?? [],
  );
  const canView = permissions.includes("ai.gateway.approvals.view");
  const query = useQuery({
    queryKey: ["assistant-approval", owner, id],
    queryFn: () => assistantApi.approvals(id),
    enabled: canView,
    refetchInterval: 4000,
  });
  const decide = useMutation({
    mutationFn: (action: "approve" | "reject" | "cancel") =>
      assistantApi.decide(id, action),
    onSuccess: () => {
      void query.refetch();
      message.success("审批状态已更新");
    },
    onError: () => message.error("审批未完成，请核对最新状态与权限"),
  });
  if (!canView)
    return (
      <Typography.Paragraph type="secondary">
        申请已提交，当前账号没有审批查看权限。
      </Typography.Paragraph>
    );
  if (query.isError)
    return (
      <Button onClick={() => void query.refetch()}>审批读取失败，重试</Button>
    );
  const request = query.data;
  if (!request)
    return (
      <Typography.Paragraph type="secondary">
        {query.isPending ? "正在读取审批…" : "审批记录不可用"}
      </Typography.Paragraph>
    );
  return (
    <div className="app-assistant-approval">
      <Typography.Text strong>{request.toolName}</Typography.Text>
      <Tag>{request.status}</Tag>
      <pre>{JSON.stringify(request.toolInput, null, 2)}</pre>
      {continuesTask ? (
        <Typography.Paragraph type="secondary">
          审批结果会继续推进原任务；助手等待领域执行与验收回执后再回答。
        </Typography.Paragraph>
      ) : null}
      {!readOnly && request.status === "pending" ? (
        <Space>
          {(["approve", "reject", "cancel"] as const)
            .filter((action) =>
              permissions.includes(`ai.gateway.approvals.${action}`),
            )
            .map((action) => (
              <Button
                key={action}
                disabled={decide.isPending}
                onClick={() => {
                  if (action === "approve")
                    confirmation.current = modal.confirm({
                      title: "批准并执行已保存的变更？",
                      content: (
                        <pre>{JSON.stringify(request.toolInput, null, 2)}</pre>
                      ),
                      okText: "批准并执行",
                      cancelText: "返回",
                      onOk: () => decide.mutateAsync(action),
                    });
                  else decide.mutate(action);
                }}
              >
                {
                  { approve: "批准", reject: "拒绝", cancel: "取消申请" }[
                    action
                  ]
                }
              </Button>
            ))}
        </Space>
      ) : null}
    </div>
  );
}

function AssistantAppearanceResult({
  metadata,
  busy,
  onContinue,
  onUndo,
}: {
  metadata?: Record<string, unknown>;
  busy?: boolean;
  onContinue: () => void;
  onUndo: () => void;
}) {
  const image = metadata?.assistantImage as
    { avatarUrl?: string; avatarPosterUrl?: string } | undefined;
  const source = image?.avatarPosterUrl || image?.avatarUrl;
  const valid =
    source && /^data:image\/(png|jpeg|gif|webp);base64,/.test(source);
  const updated =
    metadata?.assistantProfileUpdated === true &&
    !!metadata.assistantProfileApplied;
  if (!valid && !updated) return null;
  return (
    <div className="app-assistant-chat-result">
      {valid && <img src={source} alt="助手形象" />}
      {updated && (
        <Space>
          <Button type="text" disabled={busy} onClick={onContinue}>
            继续调整
          </Button>
          <Button type="text" disabled={busy} onClick={onUndo}>
            撤销这次更改
          </Button>
        </Space>
      )}
    </div>
  );
}
