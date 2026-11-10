import {
  DownOutlined,
  BookOutlined,
  FolderOpenOutlined,
} from "@ant-design/icons";
import { useEffect, useState } from "react";
import {
  Alert,
  App,
  Button,
  Checkbox,
  Input,
  Modal,
  Popconfirm,
  Popover,
  Progress,
  Select,
  Segmented,
  Space,
  Switch,
  Typography,
} from "antd";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import type {
  AIMemoryRecord,
  AIMemoryPolicy,
  WorkbenchMessage,
  WorkbenchSession,
  WorkbenchModelPreferences,
} from "@opensoha/contracts/gen/ts/sohaapi";
import { assistantApi } from "@/assistant-api";
import { selectAssistantOwner, useAppStore } from "@/store";

const memoryReadEnabled = (policy?: AIMemoryPolicy) => Boolean(policy?.enabled && (policy.readEnabled ?? policy.enabled));
const memoryWriteEnabled = (policy?: AIMemoryPolicy) => Boolean(policy?.enabled && (policy.writeEnabled ?? policy.enabled));

export type AssistantBackgroundSelection = {
  modelPreferences?: WorkbenchModelPreferences;
  knowledgeBaseIds?: string[];
  memoryIds?: string[];
};

export function sessionBackground(
  metadata?: WorkbenchSession["metadata"],
): AssistantBackgroundSelection {
  const model = metadata?.modelPreferences;
  const knowledge = metadata?.knowledgeContext;
  return {
    modelPreferences:
      model && typeof model === "object"
        ? {
            ...(typeof model.publicModel === "string"
              ? { publicModel: model.publicModel.slice(0, 256) }
              : {}),
            ...(model.reasoningEffort ? { reasoningEffort: model.reasoningEffort } : {}),
          }
        : undefined,
    knowledgeBaseIds:
      knowledge &&
      typeof knowledge === "object" &&
      "enabled" in knowledge &&
      knowledge.enabled === true &&
      "knowledgeBaseIds" in knowledge &&
      Array.isArray(knowledge.knowledgeBaseIds)
        ? knowledge.knowledgeBaseIds
            .filter(
              (value): value is string =>
                typeof value === "string" && value.length <= 256,
            )
            .slice(0, 20)
        : [],
  };
}

export function AssistantBackground({
  selection,
  onChange,
  mode = "heya",
}: {
  mode?: "chat" | "heya";
  selection: AssistantBackgroundSelection;
  onChange: (value: AssistantBackgroundSelection) => void;
}) {
  const bootstrap = useAppStore((state) => state.bootstrap);
  const owner = bootstrap?.currentUser.userId;
  const permissions = bootstrap?.permissionSnapshot.permissionKeys ?? [];
  const [open, setOpen] = useState(false);
  const [memoryOpen, setMemoryOpen] = useState(false);
  const knowledge = useQuery({
    queryKey: ["assistant-knowledge", owner],
    queryFn: assistantApi.knowledgeBases,
    enabled: open && permissions.includes("ai.knowledge.view"),
  });
  const patch = (values: Partial<AssistantBackgroundSelection>) =>
    onChange({ ...selection, ...values });
  return (
    <>
      <Button
        type="text"
        icon={<FolderOpenOutlined />}
        onClick={() => setOpen(true)}
      >
        添加背景
      </Button>
      {permissions.includes("ai.memory.view") ? (
        <Button
          type="text"
          icon={<BookOutlined />}
          onClick={() => setMemoryOpen(true)}
        >
          个人记忆
          {selection.memoryIds?.length
            ? ` · ${selection.memoryIds.length}`
            : ""}
        </Button>
      ) : null}
      <Modal
        open={open}
        title="添加背景"
        onCancel={() => setOpen(false)}
        footer={<Button onClick={() => setOpen(false)}>完成</Button>}
      >
        <Typography.Paragraph type="secondary">
          选择用于当前话题。实际使用的资料以服务端保存的回复来源为准。
        </Typography.Paragraph>
        <Space orientation="vertical" style={{ width: "100%" }}>
          <Typography.Text strong>知识库</Typography.Text>
          <Select
            aria-label="知识库"
            mode="multiple"
            maxCount={20}
            style={{ width: "100%" }}
            value={selection.knowledgeBaseIds ?? []}
            options={(knowledge.data ?? [])
              .filter((base) => base.status === "active")
              .map((base) => ({ value: base.id, label: base.name }))}
            onChange={(knowledgeBaseIds: string[]) =>
              patch({ knowledgeBaseIds })
            }
            disabled={!permissions.includes("ai.knowledge.view")}
          />
          {knowledge.isError ? (
            <Alert type="error" title="背景读取失败，请核对权限后重新打开。" />
          ) : null}
        </Space>
      </Modal>
      {memoryOpen ? (
        <MemoryEditor
          mode={mode}
          selection={selection.memoryIds ?? []}
          onChange={(memoryIds) => patch({ memoryIds })}
          onClose={() => setMemoryOpen(false)}
        />
      ) : null}
    </>
  );
}

export function AssistantModel({
  selection,
  profilePreferences,
  onChange,
  disabled,
}: {
  selection: AssistantBackgroundSelection;
  profilePreferences?: WorkbenchModelPreferences;
  onChange: (value: AssistantBackgroundSelection) => void;
  disabled: boolean;
}) {
  const bootstrap = useAppStore((state) => state.bootstrap);
  const owner = useAppStore(selectAssistantOwner);
  const [open, setOpen] = useState(false);
  const catalog = useQuery({
    queryKey: ["assistant-catalog", owner],
    queryFn: assistantApi.catalog,
    enabled:
      bootstrap?.permissionSnapshot.permissionKeys.includes(
        "observe.ai.chat",
      ) ?? false,
  });
  const fallbackModel = profilePreferences?.publicModel || catalog.data?.defaultPublicModel;
  const model = selection.modelPreferences?.publicModel || fallbackModel;
  const modelOption = catalog.data?.modelOptions?.find((item) => item.publicModel === model);
  const configuredEffort = selection.modelPreferences?.reasoningEffort;
  const profileEffort = profilePreferences?.reasoningEffort;
  const effort = configuredEffort || profileEffort || "auto";
  const efforts = modelOption?.reasoningEfforts ?? [];
  const unsupportedEffort = effort !== "auto" && !efforts.includes(effort);
  const labels = { auto: "自动", low: "轻度", medium: "标准", high: "深度" };
  const capacity = usageCount(usageRecord(modelOption).contextWindowTokens);
  const label = model || "默认模型";
  return (
    <Popover
      fresh
      trigger="click"
      placement="topRight"
      arrow={false}
      open={open && !disabled}
      onOpenChange={(next) => {
        setOpen(next);
        if (next && catalog.isError) void catalog.refetch();
      }}
      content={
        <div
          className="app-assistant-model-menu"
          onKeyDown={(event) => {
            if (event.key === "Escape") setOpen(false);
          }}
        >
          <Typography.Text type="secondary">模型</Typography.Text>
          <Select
            aria-label="模型"
            showSearch={{ optionFilterProp: "label" }}
            disabled={disabled || catalog.isPending || catalog.isError}
            style={{ width: "100%" }}
            value={selection.modelPreferences?.publicModel || ""}
            options={[
              {
                value: "",
                label: fallbackModel
                  ? `${profilePreferences?.publicModel ? "配置" : "默认"} · ${fallbackModel}`
                  : "默认模型",
              },
              ...(catalog.data?.modelOptions ?? []).map((item) => ({
                value: item.publicModel,
                label: item.publicModel,
              })),
            ]}
            onChange={(publicModel: string) =>
              onChange({
                ...selection,
                modelPreferences: publicModel
                  ? { publicModel, reasoningEffort: "auto" }
                  : undefined,
              })
            }
          />
          <Typography.Text type="secondary">思考强度</Typography.Text>
          <Segmented
            block
            aria-label="思考强度"
            disabled={disabled || (!efforts.length && !unsupportedEffort && !profileEffort)}
            value={profileEffort && !configuredEffort ? "inherit" : effort}
            options={[
              ...["auto" as const, ...efforts].map((value) => ({ value, label: labels[value] })),
              ...(profileEffort ? [{ value: "inherit", label: `配置 · ${labels[profileEffort]}` }] : []),
              ...(unsupportedEffort && configuredEffort ? [{ value: effort, label: labels[effort], disabled: true }] : []),
            ]}
            onChange={(reasoningEffort) =>
              onChange({
                ...selection,
                modelPreferences: {
                  ...selection.modelPreferences,
                  reasoningEffort:
                    reasoningEffort === "inherit" ? undefined : reasoningEffort as WorkbenchModelPreferences["reasoningEffort"],
                },
              })
            }
          />
          {unsupportedEffort ? (
            <Typography.Text type="warning">当前模型未确认支持此思考强度，请调整模型或强度。</Typography.Text>
          ) : !efforts.length && (
            <Typography.Text type="secondary">
              当前模型自动管理思考强度
            </Typography.Text>
          )}
          <Typography.Text type="secondary">
            配置窗口：{capacity ? tokenLabel(capacity) + " tokens" : "未配置"}
          </Typography.Text>
          {catalog.isError && (
            <Alert type="error" title="模型读取失败，请重新打开重试。" />
          )}
        </div>
      }
    >
      <Button
        type="text"
        className="app-assistant-model-trigger"
        aria-label="模型与思考强度"
        aria-expanded={open}
        disabled={disabled}
      >
        <span className="app-assistant-model-name" title={label}>
          {label}
        </span>
        <span className="app-assistant-model-effort">{labels[effort]}</span>
        <DownOutlined />
      </Button>
    </Popover>
  );
}

export function hasMemoryDegradation(value: unknown): boolean {
  const record = (input: unknown): Record<string, unknown> => input && typeof input === "object" && !Array.isArray(input) ? input as Record<string, unknown> : {};
  const root = record(value);
  return [root, record(root.metadata), record(root.output), record(root.sessionPatch)].some(item =>
    item.memoryStatus === "degraded" || [item, record(item.contextSnapshot), record(item.contextEnvelope)].some(snapshot =>
      Array.isArray(snapshot.truncations) && snapshot.truncations.includes("memory_unavailable"),
    ),
  );
}

export function MessageBackground({ item }: { item: WorkbenchMessage }) {
  const value =
    item.metadata?.contextSnapshot ?? item.metadata?.contextEnvelope;
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const snapshot = value as Record<string, unknown>;
  const citations = Array.isArray(snapshot.citations)
    ? snapshot.citations
        .slice(0, 20)
        .filter(
          (citation): citation is Record<string, unknown> =>
            Boolean(citation) &&
            typeof citation === "object" &&
            !Array.isArray(citation),
        )
    : [];
  const usage = snapshot.budgetUsage;
  const tokens =
    usage && typeof usage === "object" && "evidenceTokens" in usage
      ? usage.evidenceTokens
      : undefined;
  const truncations = Array.isArray(snapshot.truncations)
    ? snapshot.truncations
        .filter((value): value is string => typeof value === "string")
        .slice(0, 5)
    : [];
  const text = (value: unknown) =>
    typeof value === "string" ? value.slice(0, 512) : "";
  return (
    <Popover
      trigger="click"
      title="实际背景与来源"
      content={
        <div style={{ maxWidth: "min(320px, 80vw)", overflowWrap: "anywhere" }}>
          {citations.length ? (
            citations.map((citation, index) => (
              <Typography.Paragraph key={text(citation.id) || index}>
                {text(citation.documentTitle) || "已授权资料"}
                {text(citation.documentVersionId)
                  ? ` · 版本 ${text(citation.documentVersionId)}`
                  : ""}
                <br />
                <Typography.Text copyable>
                  {text(citation.uri) || text(citation.id)}
                </Typography.Text>
              </Typography.Paragraph>
            ))
          ) : (
            <Typography.Paragraph>
              本条消息没有已保存的引用来源。
            </Typography.Paragraph>
          )}
          {typeof tokens === "number" &&
          Number.isFinite(tokens) &&
          tokens >= 0 ? (
            <Typography.Paragraph type="secondary">
              证据用量估算 {tokens} tokens，仅含背景资料。
            </Typography.Paragraph>
          ) : null}
          {truncations.length ? (
            <Typography.Paragraph type="secondary">
              资料裁剪：
              {truncations.map((value) => value === "memory_unavailable" ? "长期记忆暂不可用，本次对话不使用无法读取的记忆" : value.slice(0, 512)).join("；")}
            </Typography.Paragraph>
          ) : null}
        </div>
      }
    >
      <Button size="small" type="text">
        实际背景与来源
      </Button>
    </Popover>
  );
}

export function MemoryEditor({
  selection,
  onChange,
  onClose,
  initial,
  mode = "heya",
}: {
  mode?: "chat" | "heya";
  selection: string[];
  onChange: (ids: string[]) => void;
  onClose: () => void;
  initial?: { fact: string; refs: string[] };
}) {
  const { message } = App.useApp();
  const client = useQueryClient();
  const bootstrap = useAppStore((state) => state.bootstrap);
  const owner = bootstrap?.currentUser.userId;
  const canWrite =
    bootstrap?.permissionSnapshot.permissionKeys.includes("ai.memory.update") ??
    false;
  const [fact, setFact] = useState(initial?.fact.slice(0, 2000) ?? "");
  const [editing, setEditing] = useState<AIMemoryRecord>();
  const [policyKey, setPolicyKey] = useState<string>();
  const records = useQuery({
    queryKey: ["assistant-memory", owner],
    queryFn: assistantApi.memories,
    refetchInterval: 3000,
  });
  useEffect(() => {
    const quarantined = new Set(records.data?.filter(record => record.quarantined).map(record => record.id));
    const allowed = selection.filter(id => !quarantined.has(id));
    if (allowed.length !== selection.length) onChange(allowed);
  }, [records.data, selection, onChange]);
  const policies = useQuery({
    queryKey: ["assistant-memory-policies", owner],
    queryFn: assistantApi.memoryPolicies,
  });
  const activePolicies = (policies.data ?? []).filter(
    (policy) =>
      (!policies.data?.some(item => item.ownerId === owner && item.mode === mode) || (policy.ownerId === owner && policy.mode === mode)) &&
      memoryWriteEnabled(policy) &&
      (!policy.mode || policy.mode === mode) &&
      (!policy.ownerId || policy.ownerId === owner) &&
      policy.ownerTypes.includes("user"),
  );
  const policy =
    activePolicies.find((item) => `${item.id}:${item.version}` === policyKey) ??
    activePolicies[0];
  const personalPolicy = policies.data?.find(item => item.ownerId === owner && item.mode === mode);
  const effectivePolicy = personalPolicy ?? policies.data?.find(item => !item.ownerId && (!item.mode || item.mode === mode) && item.enabled);
  const changePolicy = useMutation({
    mutationFn: (change: {readEnabled?: boolean; writeEnabled?: boolean; automatic?: boolean}) => assistantApi.saveMemoryPolicy({
      id: personalPolicy?.id ?? `personal-${mode}`, name: `${mode} 个人记忆`, mode,
      ttlDays: Math.max(1, Math.round((personalPolicy?.defaultTtl ?? 30 * 864e11) / 864e11)),
      consentMode: change.automatic === true ? "automatic" : change.automatic === false ? "explicit" : personalPolicy?.explicitWriteOnly === false ? "automatic" : "explicit",
      readEnabled: change.readEnabled ?? memoryReadEnabled(effectivePolicy),
      writeEnabled: change.writeEnabled ?? memoryWriteEnabled(effectivePolicy),
    }),
    onSuccess: async (_, change) => {
      if (change.readEnabled === false) onChange([]);
      await client.invalidateQueries({queryKey: ["assistant-memory-policies", owner]});
      message.success("授权已更新；关闭后停止后续使用，历史对话保留。");
    },
  });
  const save = useMutation({
    mutationFn: async () => {
      if (!owner || !policy || !fact.trim() || !canWrite ||
          (editing && records.data?.find(record => record.id === editing.id)?.quarantined))
        throw new Error("需要有效个人记忆策略与写入权限。");
      const now = new Date();
      const digest = await crypto.subtle.digest(
        "SHA-256",
        new TextEncoder().encode(`user:${owner}`),
      );
      const scopeHash =
        "sha256:" +
        Array.from(new Uint8Array(digest), (value) =>
          value.toString(16).padStart(2, "0"),
        ).join("");
      return assistantApi.saveMemory({
        policyId: policy.id,
        policyVersion: policy.version,
        record: {
          id: editing?.id ?? crypto.randomUUID(),
          ownerType: "user",
          ownerId: owner,
          scopeHash,
          fact: fact.trim(),
          sourceType: "explicit_user",
          sourceRefs: editing?.sourceRefs ?? initial?.refs ?? [],
          confidence: 1,
          validFrom: now.toISOString(),
          expiresAt: new Date(
            now.getTime() + policy.defaultTtl / 1e6,
          ).toISOString(),
          policyVersion: policy.version,
          status: "active",
          createdAt: editing?.createdAt ?? now.toISOString(),
        },
      });
    },
    onSuccess: async () => {
      await client.invalidateQueries({ queryKey: ["assistant-memory", owner] });
      setEditing(undefined);
      setFact("");
      message.success("个人记忆已接收；同步状态以列表为准。");
    },
  });
  const remove = useMutation({
    mutationFn: assistantApi.deleteMemory,
    onSuccess: async (_, id) => {
      onChange(selection.filter((item) => item !== id));
      if (editing?.id === id) { setEditing(undefined); setFact(""); }
      await client.invalidateQueries({ queryKey: ["assistant-memory", owner] });
    },
  });
  const recordMode = (record: AIMemoryRecord) => policies.data?.find(item => item.id === record.policyId)?.mode;
  return (
    <Modal
      open
      title="个人记忆"
      onCancel={onClose}
      footer={<Space><Button disabled={!selection.length} onClick={() => onChange([])}>清空本次选择</Button><Button onClick={onClose}>完成</Button></Space>}
    >
      <Typography.Paragraph type="secondary">
        Chat 仅显式保存；Heya 自动记忆需主动启用。勾选本人另一入口的记忆后，共享至本次会话；默认不跨入口选择。删除或撤权立即停止后续使用，后台传播状态如下，历史对话保留。关闭记忆不影响普通聊天。
      </Typography.Paragraph>
      {canWrite ? <Space orientation="vertical">
        <Typography.Text>{mode === "chat" ? "Chat" : "Heya"} 记忆授权</Typography.Text>
        <Space>允许读取<Switch aria-label="允许读取记忆" checked={memoryReadEnabled(effectivePolicy)} disabled={changePolicy.isPending || policies.isError} onChange={readEnabled => changePolicy.mutate({readEnabled})} /></Space>
        <Space>允许写入<Switch aria-label="允许写入记忆" checked={memoryWriteEnabled(effectivePolicy)} disabled={changePolicy.isPending || policies.isError} onChange={writeEnabled => changePolicy.mutate({writeEnabled})} /></Space>
        {mode === "heya" ? <Space>自动记忆（主动授权）<Switch aria-label="Heya 自动记忆" checked={Boolean(personalPolicy?.enabled && personalPolicy.explicitWriteOnly === false)} disabled={changePolicy.isPending || policies.isError} onChange={automatic => changePolicy.mutate({automatic})} /></Space> : null}
      </Space> : null}
      {records.isError || policies.isError ? (
        <Alert type="error" title="记忆读取失败或当前不可用。" />
      ) : null}
      {(records.data ?? [])
        .filter(
          (record) =>
            record.ownerType === "user" &&
            record.ownerId === owner,
        )
        .map((record) => (
          <div key={record.id} style={{ marginBottom: 16 }}>
            <Typography.Text type="secondary">{recordMode(record) === "chat" ? "Chat" : recordMode(record) === "heya" ? "Heya" : "历史共享"} · 同步状态：{({pending: "保存中", synced: "已同步", delete_pending: "已禁用，删除传播中", deleted: "已删除", error: "外部同步失败，使用前仍校验权限与来源", disabled: "未同步至外部记忆"} as Record<string, string>)[record.syncStatus ?? ""] ?? "历史记录"}</Typography.Text>
            {record.quarantined ? <Alert type="warning" title="已隔离，待核对" description={record.quarantineReason || "此条记忆暂不可引用或改正，请核对来源；可删除。"} /> : null}
            {record.status === "deleted" || record.deletedAt ? <Typography.Paragraph>已停止使用此条记忆。</Typography.Paragraph> : <>
            <Checkbox
              checked={selection.includes(record.id)}
              disabled={
                record.quarantined === true || record.status !== "active" || Boolean(record.deletedAt) || !record.expiresAt || Date.parse(record.expiresAt) <= Date.now() || Date.parse(record.validFrom) > Date.now() || (personalPolicy !== undefined && !memoryReadEnabled(personalPolicy)) ||
                !(policies.data ?? []).some(
                  (policy) =>
                    memoryReadEnabled(policy) &&
                    policy.id === record.policyId &&
                    policy.version === record.policyVersion,
                )
              }
              onChange={(event) =>
                onChange(
                  event.target.checked
                    ? [...new Set([...selection, record.id])].slice(0, 20)
                    : selection.filter((id) => id !== record.id),
                )
              }
            >
              {record.fact}
            </Checkbox>
            <Typography.Paragraph type="secondary">
              有效期至{" "}
              {record.expiresAt
                ? new Date(record.expiresAt).toLocaleString()
                : "未知"}
            </Typography.Paragraph>
            <Typography.Paragraph type="secondary">来源：{record.sourceRefs?.length ? record.sourceRefs.join(" · ") : "用户明确提供"}</Typography.Paragraph>
            {Object.entries(record.sourceHashes ?? {}).map(([source, hash]) => <Typography.Paragraph key={source} type="secondary">来源校验：{source} · {hash}</Typography.Paragraph>)}
            {recordMode(record) && recordMode(record) !== mode ? <Typography.Paragraph type="secondary">请到 {recordMode(record) === "heya" ? "Heya" : "Chat"} 入口改正，保留原记忆范围。</Typography.Paragraph> : null}
            {canWrite ? (
              <Space>
                <Button
                  size="small"
                  disabled={record.quarantined === true || Boolean(recordMode(record) && recordMode(record) !== mode)}
                  title={recordMode(record) && recordMode(record) !== mode ? `请到 ${recordMode(record) === "heya" ? "Heya" : "Chat"} 入口改正，保留原记忆范围` : undefined}
                  onClick={() => {
                    setEditing(record);
                    setFact(record.fact);
                    setPolicyKey(`${record.policyId}:${record.policyVersion}`);
                  }}
                >
                  改正
                </Button>
                <Popconfirm
                  title="删除这条个人记忆？"
                  onConfirm={() => remove.mutateAsync(record.id)}
                >
                  <Button size="small" danger disabled={remove.isPending}>
                    删除
                  </Button>
                </Popconfirm>
              </Space>
            ) : null}
            </>}
          </div>
        ))}
      {canWrite ? (
        <Space orientation="vertical" style={{ width: "100%" }}>
          <Input.TextArea
            aria-label="记忆内容"
            value={fact}
            maxLength={2000}
            rows={4}
            onChange={(event) => setFact(event.target.value)}
          />
          <Select
            aria-label="记忆保留策略"
            style={{ width: "100%" }}
            value={policy ? `${policy.id}:${policy.version}` : undefined}
            onChange={setPolicyKey}
            options={activePolicies.map((policy) => ({
              value: `${policy.id}:${policy.version}`,
              label: `${policy.id} · ${Math.round(policy.defaultTtl / 864e11)} 天`,
            }))}
          />
          <Button
            type="primary"
            disabled={
              !policy || !fact.trim() || records.isError || policies.isError || Boolean(editing && records.data?.find(record => record.id === editing.id)?.quarantined)
            }
            loading={save.isPending}
            onClick={() => save.mutate()}
          >
            确认保存个人记忆
          </Button>
        </Space>
      ) : null}
      {save.isError || remove.isError || changePolicy.isError ? (
        <Alert
          type="error"
          title="记忆变更未确认，请核对最新状态；输入已保留。"
        />
      ) : null}
    </Modal>
  );
}

function usageRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}
function usageCount(value: unknown): number | undefined {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0
    ? value
    : undefined;
}
function tokenLabel(value: number) {
  return value >= 1000
    ? `${new Intl.NumberFormat("zh-CN", { maximumFractionDigits: 1 }).format(value / 1000)}K`
    : value.toLocaleString("zh-CN");
}
export function AssistantContextUsage({ item }: { item?: WorkbenchMessage }) {
  const [open, setOpen] = useState(false);
  const usage = usageRecord(item?.metadata?.contextUsage);
  const measured =
    usage.measurement === "reported" || usage.measurement === "estimated";
  const input = measured ? usageCount(usage.inputTokens) : undefined;
  const output = measured ? usageCount(usage.outputTokens) : undefined;
  const capacity = usageCount(usage.contextWindowTokens) || undefined;
  const estimated = usage.measurement === "estimated";
  const count = (value: number | undefined) =>
    value === undefined
      ? "未知"
      : `${estimated ? "估算 " : ""}${tokenLabel(value)} tokens`;
  const label = `上下文 ${input === undefined ? "未知" : (estimated ? "约 " : "") + tokenLabel(input)}${capacity ? " / " + tokenLabel(capacity) : ""}`;
  const percent =
    input !== undefined && capacity ? (input / capacity) * 100 : undefined;
  return (
    <Popover
      fresh
      trigger="click"
      placement="top"
      arrow={false}
      title="上下文用量"
      open={open}
      onOpenChange={setOpen}
      content={
        <div
          className="app-assistant-context-usage"
          onKeyDown={(event) => {
            if (event.key === "Escape") setOpen(false);
          }}
        >
          <strong>{label}</strong>
          {input !== undefined && capacity && (
            <progress
              value={Math.min(input, capacity)}
              max={capacity}
              aria-label={`${estimated ? "估算" : ""}输入占模型窗口`}
            />
          )}
          <dl>
            <div>
              <dt>本次模型</dt>
              <dd>
                {typeof usage.model === "string" ? usage.model : "未记录"}
              </dd>
            </div>
            <div>
              <dt>输入用量</dt>
              <dd>{count(input)}</dd>
            </div>
            <div>
              <dt>输出用量</dt>
              <dd>{count(output)}</dd>
            </div>
            <div>
              <dt>模型窗口</dt>
              <dd>
                {capacity
                  ? tokenLabel(capacity) + " tokens · 路由配置"
                  : "容量未配置"}
              </dd>
            </div>
            <div>
              <dt>计量来源</dt>
              <dd>
                {estimated
                  ? "按输入与输出估算"
                  : measured
                    ? "模型上游回报"
                    : "尚无用量回报"}
              </dd>
            </div>
          </dl>
          <p>
            最近一次模型调用，包含系统提示、历史、背景与工具定义，不是当前草稿的预测用量。
          </p>
          {item && <MessageBackground item={item} />}
        </div>
      }
    >
      <Button
        type="text"
        shape="circle"
        className={
          "app-assistant-context-trigger" +
          (percent === undefined ? " is-unknown" : "")
        }
        title={label}
        aria-label="上下文用量与背景来源"
        aria-expanded={open}
        onKeyDown={(event) => {
          if (event.key === "Escape") setOpen(false);
        }}
      >
        <Progress
          aria-hidden="true"
          type="circle"
          size={14}
          strokeWidth={12}
          status="normal"
          showInfo={false}
          percent={Math.min(100, percent ?? 0)}
          steps={percent === undefined ? { count: 8, gap: 8 } : undefined}
          strokeColor="currentColor"
          railColor={percent === undefined ? "currentColor" : "var(--border)"}
        />
      </Button>
    </Popover>
  );
}

export function TaskUsage({ value }: { value: unknown }) {
  const usage = usageRecord(value);
  const total = usageCount(usage.totalTokens);
  if (total === undefined) return null;
  const limit = usageCount(usage.taskTokenLimit);
  return (
    <details className="app-assistant-task-usage">
      <summary>任务用量</summary>
      <p>
        累计消耗：{usage.estimatedTokens ? "估算 " : ""}
        {tokenLabel(total)} tokens
      </p>
      {limit ? <p>任务预算：{tokenLabel(limit)} tokens</p> : null}
      <p>多次模型调用的累计输入与输出，不代表上下文窗口占用。</p>
    </details>
  );
}
