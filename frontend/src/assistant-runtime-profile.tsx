import { Button, Popover, Select, Space, Tag, Typography } from "antd";
import type { WorkbenchAgentRun } from "@opensoha/contracts/gen/ts/sohaapi";
import type { AssistantRuntimeProfile } from "./assistant-api";

const states = {
  preparing: { label: "准备中", color: "processing" },
  confirmed: { label: "装配已确认", color: "success" },
  degraded: { label: "已降级", color: "warning" },
  rejected: { label: "已拒绝", color: "error" },
};
const kinds = { mcp: "MCP", skill: "Skill", hook: "Hook" };
const reasons = new Map([
  ["asset_unavailable", "指定版本不可用"],
  ["asset_initialization_failed", "初始化失败"],
  ["dependency_unavailable", "所需依赖不可用"],
]);
const hookOutcomeLabels = {
  completed: "已完成",
  denied: "已拒绝",
  failed: "失败",
  canceled: "已取消",
  unknown: "结果未知",
};

interface HookOutcome {
  id: string;
  version: string;
  callId: string;
  toolName: string;
  outcome: keyof typeof hookOutcomeLabels;
}

function readHookOutcomes(value: unknown): HookOutcome[] {
  if (!Array.isArray(value)) return [];
  return value.filter(
    (item): item is HookOutcome =>
      item &&
      typeof item.id === "string" && /^[a-z0-9][a-z0-9-]{0,47}$/.test(item.id) &&
      typeof item.version === "string" && /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(item.version) &&
      typeof item.callId === "string" && item.callId.length > 0 &&
      typeof item.toolName === "string" && /^[A-Za-z0-9_.:/-]{1,128}$/.test(item.toolName) &&
      typeof item.outcome === "string" &&
      Object.prototype.hasOwnProperty.call(hookOutcomeLabels, item.outcome),
  );
}

interface RuntimeAssembly {
  profileId: string;
  revision: number;
  status: keyof typeof states;
  assets: {
    kind: keyof typeof kinds;
    id: string;
    version: string;
    status: "loaded" | "unavailable";
    code?: string;
  }[];
}

function readAssembly(value: unknown): RuntimeAssembly | undefined {
  if (!value || typeof value !== "object") return;
  const assembly = value as Partial<RuntimeAssembly>;
  if (
    typeof assembly.profileId === "string" &&
    Number.isSafeInteger(assembly.revision) &&
    typeof assembly.status === "string" &&
    Object.prototype.hasOwnProperty.call(states, assembly.status) &&
    Array.isArray(assembly.assets) &&
    assembly.assets.every(
      (asset) =>
        asset &&
        Object.prototype.hasOwnProperty.call(kinds, asset.kind) &&
        typeof asset.id === "string" &&
        typeof asset.version === "string" &&
        ["loaded", "unavailable"].includes(asset.status),
    )
  ) return assembly as RuntimeAssembly;
}

export function AssistantRuntimeAssembly({
  value,
  fallback,
  hookOutcomes,
  toolExecutions,
}: {
  value: unknown;
  fallback?: unknown;
  hookOutcomes?: unknown;
  toolExecutions?: WorkbenchAgentRun["toolExecutions"];
}) {
  const assembly = readAssembly(value) ?? readAssembly(fallback);
  const hooks = readHookOutcomes(hookOutcomes);
  if (!assembly && !hooks.length) return null;
  const status = assembly && states[assembly.status];
  const identity = assembly ? `${assembly.profileId}${assembly.revision ? ` · v${assembly.revision}` : ""}` : "";
  return (
    <Space size={4} wrap>
      {status && <Tag color={status.color}>{status.label}</Tag>}
      <Popover
        trigger="click"
        title="本轮运行装配"
        content={
          <Space orientation="vertical" size={4} style={{ maxHeight: "min(320px, 50vh)", overflowY: "auto" }}>
            {identity && <Typography.Text>{identity}</Typography.Text>}
            {assembly?.assets.map((asset) => (
              <Typography.Text key={`${asset.kind}:${asset.id}`}>
                {kinds[asset.kind]} · {asset.id} @ {asset.version} ·{" "}
                {asset.status !== "loaded" ? reasons.get(asset.code ?? "") ?? "不可用"
                  : asset.kind === "skill" ? "目录已注册" : "已加载"}
                {asset.kind === "skill" && asset.status === "loaded" && toolExecutions?.some(
                  (tool) => tool.adapterId === asset.id && tool.toolName === `skill_${asset.id.replace(/-/g, "_")}_load` && tool.status === "completed",
                ) && " · 正文已加载"}
              </Typography.Text>
            ))}
            {assembly?.status === "rejected" && <span>运行配置或必需能力不可用，请检查配置后重试。</span>}
            {assembly?.status === "confirmed" && !assembly.assets.length && <span>本轮无附加能力</span>}
            {hooks.length > 0 && <Typography.Text strong>Hook 执行结果</Typography.Text>}
            {hooks.map((hook, index) => (
              <Typography.Text key={`${hook.id}:${hook.callId}:${index}`}>
                {hook.id} @ {hook.version} · {hook.toolName} · {hookOutcomeLabels[hook.outcome]}
              </Typography.Text>
            ))}
          </Space>
        }
      >
        <Button size="small" type="text" aria-label="查看本轮装配详情">
          {identity || "Hook 执行结果"}{hooks.length > 0 ? ` · ${hooks.length} 条 Hook 记录` : ""}
        </Button>
      </Popover>
    </Space>
  );
}

export function AssistantRuntimeProfileControl({
  profiles,
  scope,
  profileId,
  selected,
  disabled,
  loading,
  onChange,
  onManage,
}: {
  profiles?: AssistantRuntimeProfile[];
  scope: AssistantRuntimeProfile["scope"];
  profileId: string;
  selected?: AssistantRuntimeProfile;
  disabled: boolean;
  loading: boolean;
  onChange: (profileId: string) => void;
  onManage?: (profileId: string) => void;
}) {
  const defaultId = `${scope}-default`;
  const allowed = (profiles ?? []).filter((item) => item.enabled && item.scope === scope);
  const unavailable = Boolean(profiles && profileId && !selected);
  const options = [
    { value: "", label: scope === "chat" ? "Chat 默认配置" : "Heya 默认配置" },
    ...allowed
      .filter((item) => item.id !== defaultId || profileId === defaultId)
      .map((item) => ({ value: item.id, label: `${item.name} · v${item.revision}` })),
    ...(profileId && !selected
      ? [{ value: profileId, label: unavailable ? "当前配置不可用" : "运行配置待确认", disabled: true }]
      : []),
  ];
  return (
    <Space size={6} wrap>
      <Select
        aria-label="运行配置"
        size="small"
        style={{ maxWidth: 232 }}
        value={profileId}
        disabled={disabled}
        loading={loading}
        popupMatchSelectWidth={false}
        options={options}
        onChange={onChange}
      />
      {(selected || onManage) && (
        <Popover
          trigger="click"
          title={selected ? `${selected.name} · v${selected.revision}` : "运行配置"}
          content={
            <Space orientation="vertical" size={4}>
              <Typography.Text type="secondary">已发布配置，下一轮提交时解析</Typography.Text>
              {selected?.modelPreferences?.publicModel && <span>配置默认模型 · {selected.modelPreferences.publicModel}</span>}
              {selected?.maxOutputTokens && <span>输出上限 · {selected.maxOutputTokens} tokens</span>}
              {selected?.assets?.map((asset) => (
                <span key={`${asset.kind}:${asset.id}`}>
                  {kinds[asset.kind]} · {asset.id} @ {asset.version} · {asset.required ? "必需" : "可选"}
                </span>
              ))}
              {selected && !selected.assets?.length && <span>暂无附加能力</span>}
              {onManage && <Button type="link" onClick={() => onManage(profileId || defaultId)}>在 Web 中管理</Button>}
            </Space>
          }
        >
          <Button size="small" type="text">配置详情</Button>
        </Popover>
      )}
      {unavailable && <Typography.Text type="warning">请选择其他配置或恢复默认配置</Typography.Text>}
    </Space>
  );
}
