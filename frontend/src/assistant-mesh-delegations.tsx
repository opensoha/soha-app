import { useEffect, useRef, useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import {
  Alert,
  Button,
  Card,
  Empty,
  Input,
  Select,
  Space,
  Spin,
  Tabs,
  Tag,
  Typography,
} from "antd";
import {
  ApiError,
  assistantRequest,
  meshNativeDelegation,
  requestResponse,
} from "@/api";
import { meshApi } from "@/assistant-mesh-api";
import { useAppStore } from "@/store";

export type DelegationField = "productVersion" | "buildVersion";
export type DelegationStatus =
  | "awaiting_owner_approval"
  | "approved"
  | "executing"
  | "awaiting_confirmation"
  | "completed"
  | "declined"
  | "invalidated"
  | "expired"
  | "failed";

export interface MeshDelegation {
  id: string;
  callerId: string;
  callerName: string;
  ownerId: string;
  ownerName: string;
  capability: string;
  field: DelegationField;
  inputHash: string;
  status: DelegationStatus;
  result?: unknown;
  createdAt: string;
  expiresAt: string;
  closedAt?: string;
}

type Direction = "inbox" | "sent";
type NativeAction = "device" | "execute" | "preview" | "deliver";
type NativeState =
  | "registered"
  | "canceled"
  | "completed"
  | "awaiting_confirmation"
  | "failed"
  | "unavailable";

interface NativeResult {
  state: NativeState;
  preview?: string;
}

const FIELD_LABEL: Record<DelegationField, string> = {
  productVersion: "产品版本",
  buildVersion: "构建版本",
};
const FIELDS = (Object.keys(FIELD_LABEL) as DelegationField[]).map((value) => ({
  value,
  label: FIELD_LABEL[value],
}));
const STATUS_LABEL: Record<DelegationStatus, string> = {
  awaiting_owner_approval: "等待本人批准",
  approved: "已批准",
  executing: "执行中",
  awaiting_confirmation: "等待本人确认",
  completed: "已完成",
  declined: "已拒绝",
  invalidated: "已失效",
  expired: "已过期",
  failed: "失败",
};
const STATUS_TAG: Record<DelegationStatus, string> = {
  awaiting_owner_approval: "warning",
  approved: "processing",
  executing: "processing",
  awaiting_confirmation: "warning",
  completed: "success",
  declined: "default",
  invalidated: "default",
  expired: "default",
  failed: "error",
};
const STATUSES = new Set<DelegationStatus>(
  Object.keys(STATUS_LABEL) as DelegationStatus[],
);
const NATIVE_STATES = new Set<NativeState>([
  "registered",
  "canceled",
  "completed",
  "awaiting_confirmation",
  "failed",
  "unavailable",
]);
const NATIVE_STATE_LABEL: Record<NativeState, string> = {
  registered: "本机设备已注册。",
  canceled: "本人已取消本次原生操作。",
  completed: "原生操作已完成。",
  awaiting_confirmation: "需要本人再次确认后才能交付结果。",
  failed: "原生操作失败，请查看本机提示。",
  unavailable: "当前原生环境不可用。",
};

function mismatch(message: string): never {
  throw new ApiError(502, "response_contract_mismatch", message);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function errorText(error: unknown) {
  return error instanceof Error && error.message
    ? error.message
    : "请求失败，请稍后重试";
}

function denied(error: unknown) {
  return (
    error instanceof ApiError && (error.status === 401 || error.status === 403)
  );
}

function formatTime(value: string) {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString("zh-CN");
}

function decodeDelegation(value: unknown): MeshDelegation {
  if (
    !isRecord(value) ||
    typeof value.id !== "string" ||
    typeof value.callerId !== "string" ||
    typeof value.callerName !== "string" ||
    typeof value.ownerId !== "string" ||
    typeof value.ownerName !== "string" ||
    typeof value.capability !== "string" ||
    typeof value.field !== "string" ||
    !(value.field in FIELD_LABEL) ||
    typeof value.inputHash !== "string" ||
    typeof value.status !== "string" ||
    !STATUSES.has(value.status as DelegationStatus) ||
    typeof value.createdAt !== "string" ||
    typeof value.expiresAt !== "string" ||
    (value.closedAt !== undefined && typeof value.closedAt !== "string")
  )
    return mismatch("委托回执不完整");
  return value as unknown as MeshDelegation;
}

function decodeNative(value: unknown): NativeResult {
  if (
    !isRecord(value) ||
    typeof value.state !== "string" ||
    !NATIVE_STATES.has(value.state as NativeState) ||
    (value.preview !== undefined && typeof value.preview !== "string")
  )
    return mismatch("原生代理回执不完整");
  return value as unknown as NativeResult;
}

async function fetchDelegations(direction: Direction): Promise<MeshDelegation[]> {
  const payload = (await (
    await requestResponse(
      `/copilot/assistant-mesh/delegations?direction=${encodeURIComponent(direction)}`,
    )
  ).json()) as { items?: unknown[] | null } | null;
  // Existing Core versions encode empty Go slices as null.
  const items = payload?.items === null ? [] : payload?.items;
  if (!Array.isArray(items) || items.length > 1000)
    return mismatch("委托列表回执不完整");
  return items.map(decodeDelegation);
}

async function createDelegation(input: {
  ownerId: string;
  requestId: string;
  field: DelegationField;
}) {
  const created = decodeDelegation(
    await assistantRequest("/copilot/assistant-mesh/delegations", {
      method: "POST",
      body: JSON.stringify({
        ownerId: input.ownerId,
        requestId: input.requestId,
        capability: "desktop.os-version.v1",
        field: input.field,
      }),
    }),
  );
  if (created.ownerId !== input.ownerId || created.field !== input.field)
    mismatch("委托回执与请求不匹配");
  return created;
}

async function declineDelegation(id: string) {
  const declined = decodeDelegation(
    await assistantRequest(
      `/copilot/assistant-mesh/delegations/${encodeURIComponent(id)}/decline`,
      { method: "POST", body: "{}" },
    ),
  );
  if (declined.id !== id) mismatch("拒绝回执与请求不匹配");
  return declined;
}

function resultText(result: unknown) {
  if (typeof result === "string") return result;
  if (result === undefined) return "";
  try {
    return JSON.stringify(result);
  } catch {
    return String(result);
  }
}

export function AssistantMeshDelegations({
  owner,
  userId,
}: {
  owner: string;
  userId: string;
}) {
  const nativeMac = useAppStore(
    (state) => state.host?.app.platform === "darwin",
  );
  const [tab, setTab] = useState<Direction>("inbox");
  const [term, setTerm] = useState("");
  const [employee, setEmployee] = useState<string>();
  const [field, setField] = useState<DelegationField>();
  const [notice, setNotice] = useState("");
  const [nativeNotice, setNativeNotice] = useState<{
    id?: string;
    tone: "info" | "warning" | "error";
    text: string;
    preview?: string;
  }>();
  const [deviceNotice, setDeviceNotice] = useState("");
  const requestId = useRef<{ key: string; id: string }>();

  const inboxQuery = useQuery({
    queryKey: ["assistant-mesh-delegations", owner, userId, "inbox"],
    queryFn: () => fetchDelegations("inbox"),
    enabled: Boolean(owner && userId),
    retry: false,
    staleTime: 0,
    refetchInterval: 8_000,
  });
  const sentQuery = useQuery({
    queryKey: ["assistant-mesh-delegations", owner, userId, "sent"],
    queryFn: () => fetchDelegations("sent"),
    enabled: Boolean(owner && userId) && tab === "sent",
    retry: false,
    staleTime: 0,
    refetchInterval: tab === "sent" ? 8_000 : false,
  });
  const searchQuery = useQuery({
    queryKey: ["assistant-mesh-delegations", owner, "search", term],
    queryFn: () => meshApi.search(term.trim() || undefined),
    enabled: Boolean(owner) && tab === "sent",
    retry: false,
    staleTime: 30_000,
  });

  useEffect(() => {
    setTerm("");
    setEmployee(undefined);
    setField(undefined);
    setNotice("");
    setNativeNotice(undefined);
    setDeviceNotice("");
    requestId.current = undefined;
  }, [owner, userId]);

  const inbox = (inboxQuery.data ?? []).filter(
    (item) => item.ownerId === userId,
  );
  const sent = (sentQuery.data ?? []).filter(
    (item) => item.callerId === userId,
  );
  const assistants = (searchQuery.data ?? []).filter(
    (item) => item.ownerId !== userId,
  );

  const createMutation = useMutation({
    mutationFn: createDelegation,
    onSuccess: (created) => {
      requestId.current = undefined;
      setNotice(
        `已向 ${created.ownerName} 发起${FIELD_LABEL[created.field]}请求。`,
      );
      void sentQuery.refetch();
      void inboxQuery.refetch();
    },
  });
  const declineMutation = useMutation({
    mutationFn: declineDelegation,
    onSuccess: () => {
      void inboxQuery.refetch();
      void sentQuery.refetch();
    },
  });
  const nativeMutation = useMutation({
    mutationFn: async (input: {
      action: NativeAction;
      data: { id?: string; mode?: "preview" | "direct" };
    }) => decodeNative(await meshNativeDelegation(input.action, input.data)),
    onSuccess: (result, variables) => {
      if (variables.action === "device") {
        setDeviceNotice(NATIVE_STATE_LABEL[result.state]);
      } else if (result.state === "unavailable") {
        setNativeNotice({
          id: variables.data.id,
          tone: "warning",
          text: "当前原生环境不可用（可能已冷重启或不是 macOS App）；无法预览或批准，可先拒绝该请求。",
        });
      } else {
        setNativeNotice({
          id: variables.data.id,
          tone: result.state === "failed" ? "error" : "info",
          text: NATIVE_STATE_LABEL[result.state],
          preview: result.preview,
        });
      }
      void inboxQuery.refetch();
      void sentQuery.refetch();
    },
  });

  function submit() {
    if (!employee || !field || createMutation.isPending) return;
    const key = `${employee}:${field}`;
    if (requestId.current?.key !== key)
      requestId.current = { key, id: crypto.randomUUID() };
    createMutation.mutate({
      ownerId: employee,
      requestId: requestId.current.id,
      field,
    });
  }

  function runNative(
    action: NativeAction,
    data: { id?: string; mode?: "preview" | "direct" },
  ) {
    setNativeNotice(undefined);
    nativeMutation.mutate({ action, data });
  }

  function refresh() {
    void inboxQuery.refetch();
    if (tab === "sent") void sentQuery.refetch();
  }

  const refreshing = inboxQuery.isFetching || sentQuery.isFetching;

  function delegationCard(
    item: MeshDelegation,
    role: Direction,
  ) {
    const canDecline =
      role === "inbox" &&
      item.ownerId === userId &&
      ["awaiting_owner_approval", "approved", "awaiting_confirmation"].includes(item.status);
    const nativePending = nativeMutation.isPending;
    const declinePending =
      declineMutation.isPending && declineMutation.variables === item.id;
    const ownNotice =
      nativeNotice && (nativeNotice.id === item.id || nativeNotice.id === undefined)
        ? nativeNotice
        : undefined;
    return (
      <Card
        key={`${role}-${item.id}`}
        size="small"
        title={
          <Space wrap>
            <Typography.Text>
              {item.callerName && item.ownerName ? `${item.callerName} → ${item.ownerName}` : "原委托"}
            </Typography.Text>
            <Tag color={STATUS_TAG[item.status]}>{STATUS_LABEL[item.status]}</Tag>
          </Space>
        }
      >
        <Space orientation="vertical" size={6} style={{ width: "100%" }}>
          <Typography.Text>
            冻结字段：{FIELD_LABEL[item.field]}（{item.capability}）
          </Typography.Text>
          <Typography.Text type="secondary">
            输入校验 {item.inputHash.slice(0, 12)}；有效期至{" "}
            {formatTime(item.expiresAt)}
            {item.closedAt ? `；关闭于 ${formatTime(item.closedAt)}` : ""}
          </Typography.Text>
          {item.status === "completed" ? (
            <Alert
              type={item.result === undefined ? "warning" : "success"}
              showIcon
              title="请求结果"
              description={
                item.result === undefined
                  ? "结果已按保留策略清理。"
                  : resultText(item.result)
              }
            />
          ) : null}
          {role === "inbox" && item.ownerId === userId ? (
            <Space wrap>
              {["awaiting_owner_approval", "approved"].includes(item.status) ? (
                nativeMac ? (
                  <>
                    {item.status === "approved" ? <Typography.Text type="secondary">旧票据超时后可重新批准。</Typography.Text> : null}
                    <Button
                      size="small"
                      type="primary"
                      disabled={nativePending}
                      onClick={() =>
                        runNative("execute", { id: item.id, mode: "preview" })
                      }
                    >
                      批准并在本机预览
                    </Button>
                    <Button
                      size="small"
                      disabled={nativePending}
                      onClick={() =>
                        runNative("execute", { id: item.id, mode: "direct" })
                      }
                    >
                      批准并直接回传
                    </Button>
                  </>
                ) : (
                  <Typography.Text type="secondary">
                    批准需在 macOS App 中完成；当前已连接 Web 只能查看或拒绝。
                  </Typography.Text>
                )
              ) : null}
              {item.status === "executing" && nativeMac ? (
                <Button size="small" disabled={nativePending} onClick={() => runNative("preview", { id: item.id })}>
                  重试结果上报
                </Button>
              ) : null}
              {item.status === "awaiting_confirmation" && nativeMac ? (
                <>
                <Button size="small" disabled={nativePending} onClick={() => runNative("preview", { id: item.id })}>
                  查看本机预览
                </Button>
                <Button
                  size="small"
                  type="primary"
                  disabled={nativePending}
                  onClick={() => runNative("deliver", { id: item.id })}
                >
                  确认并回传结果
                </Button>
                </>
              ) : null}
              {item.status === "awaiting_confirmation" && !nativeMac ? (
                <Typography.Text type="secondary">
                  确认需在 macOS App 中完成；当前可先拒绝。
                </Typography.Text>
              ) : null}
              {canDecline ? (
                <Button
                  size="small"
                  danger
                  disabled={declinePending}
                  loading={declinePending}
                  onClick={() => declineMutation.mutate(item.id)}
                >
                  拒绝请求
                </Button>
              ) : null}
            </Space>
          ) : null}
          {ownNotice ? (
            <Alert
              type={ownNotice.tone}
              showIcon
              title={
                ownNotice.tone === "warning"
                  ? "原生审批不可用"
                  : ownNotice.tone === "error"
                    ? "原生操作失败"
                    : "本机状态"
              }
              description={ownNotice.preview && item.status === "awaiting_confirmation"
                ? `本机预览（尚未回传）：${ownNotice.preview}`
                : ownNotice.text}
            />
          ) : null}
          {declineMutation.isError && declineMutation.variables === item.id ? (
            <Alert
              type="error"
              showIcon
              title="拒绝失败"
              description={errorText(declineMutation.error)}
            />
          ) : null}
          {nativeMutation.isError &&
          nativeMutation.variables?.data.id === item.id ? (
            <Alert
              type="error"
              showIcon
              title="原生操作失败"
              description={errorText(nativeMutation.error)}
            />
          ) : null}
        </Space>
      </Card>
    );
  }

  const inboxPane = (
    <Space orientation="vertical" size="middle" style={{ width: "100%" }}>
      <Space wrap>
        <Button size="small" loading={refreshing} onClick={refresh}>
          刷新
        </Button>
        {nativeMac ? (
          <Button
            size="small"
            loading={
              nativeMutation.isPending &&
              nativeMutation.variables?.action === "device"
            }
            onClick={() => runNative("device", {})}
          >
            注册本机设备（可选）
          </Button>
        ) : null}
      </Space>
      {deviceNotice ? (
        <Alert
          type={deviceNotice.includes("已注册") ? "success" : "warning"}
          showIcon
          title="设备注册"
          description={deviceNotice}
        />
      ) : null}
      {nativeMutation.isError &&
      nativeMutation.variables?.action === "device" ? (
        <Alert
          type="error"
          showIcon
          title="设备注册失败"
          description={errorText(nativeMutation.error)}
        />
      ) : null}
      {inboxQuery.isPending ? (
        <Spin />
      ) : inboxQuery.isError ? (
        <Alert
          type={denied(inboxQuery.error) ? "warning" : "error"}
          showIcon
          title={
            denied(inboxQuery.error)
              ? "没有查看委托的权限"
              : "委托读取失败"
          }
          description={
            denied(inboxQuery.error)
              ? "权限恢复后重新打开。"
              : errorText(inboxQuery.error)
          }
          action={
            <Button onClick={() => void inboxQuery.refetch()}>重试读取</Button>
          }
        />
      ) : inbox.length === 0 ? (
        <Empty description="暂无需要本人批准的委托" />
      ) : (
        inbox.map((item) => delegationCard(item, "inbox"))
      )}
    </Space>
  );

  const sentPane = (
    <Space orientation="vertical" size="middle" style={{ width: "100%" }}>
      <Input
        aria-label="搜索可委派的同事"
        value={term}
        allowClear
        placeholder="搜索可见同事"
        onChange={(event) => setTerm(event.target.value)}
      />
      <Select
        aria-label="选择同事"
        style={{ width: "100%" }}
        value={employee}
        placeholder="选择可见同事"
        loading={searchQuery.isPending}
        onChange={setEmployee}
        options={assistants.map((item) => ({
          value: item.ownerId,
          label: `${item.name}${item.away ? "（离开）" : ""}`,
        }))}
        notFoundContent={
          searchQuery.isPending ? <Spin size="small" /> : "没有可见同事"
        }
      />
      <Select
        aria-label="选择字段"
        style={{ width: "100%" }}
        value={field}
        placeholder="选择冻结字段"
        onChange={setField}
        options={FIELDS}
      />
      <Space wrap>
        <Button
          type="primary"
          disabled={!employee || !field || !searchQuery.isSuccess || !assistants.some((item) => item.ownerId === employee)}
          loading={createMutation.isPending}
          onClick={submit}
        >
          发起请求
        </Button>
        <Button size="small" loading={refreshing} onClick={refresh}>
          刷新
        </Button>
      </Space>
      {searchQuery.isError ? (
        <Alert
          type="error"
          showIcon
          title="同事列表读取失败"
          description={errorText(searchQuery.error)}
        />
      ) : null}
      {notice ? <Alert type="success" showIcon title="已发起" description={notice} /> : null}
      {createMutation.isError ? (
        <Alert
          type="error"
          showIcon
          title="发起失败；可原地重试"
          description={errorText(createMutation.error)}
        />
      ) : null}
      {sentQuery.isPending ? (
        <Spin />
      ) : sentQuery.isError ? (
        <Alert
          type={denied(sentQuery.error) ? "warning" : "error"}
          showIcon
          title={
            denied(sentQuery.error)
              ? "没有查看已发请求的权限"
              : "已发请求读取失败"
          }
          description={errorText(sentQuery.error)}
          action={
            <Button onClick={() => void sentQuery.refetch()}>重试读取</Button>
          }
        />
      ) : sent.length === 0 ? (
        <Empty description="还没有发出委托" />
      ) : (
        sent.map((item) => delegationCard(item, "sent"))
      )}
    </Space>
  );

  return (
    <Tabs
      activeKey={tab}
      onChange={(key) => setTab(key as Direction)}
      items={[
        { key: "inbox", label: "收到的委托", children: inboxPane },
        { key: "sent", label: "已发出", children: sentPane },
      ]}
    />
  );
}
