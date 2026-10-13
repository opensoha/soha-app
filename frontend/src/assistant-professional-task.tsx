import { useState } from "react";
import { Alert, Checkbox, Form, Input, InputNumber, Modal, Select } from "antd";
import { useQuery } from "@tanstack/react-query";
import type {
  WorkbenchSessionToolset,
  WorkbenchTaskIntent,
} from "@opensoha/contracts/gen/ts/sohaapi";
import { assistantApi } from "@/assistant-api";
import { useAppStore } from "@/store";

type Capability = NonNullable<WorkbenchTaskIntent["capabilities"]>[number];
const capabilities: Array<{
  value: Capability;
  label: string;
  permission: string;
}> = [
  {
    value: "root_cause",
    label: "根因分析",
    permission: "observe.ai.root-cause.run",
  },
  {
    value: "performance",
    label: "性能分析",
    permission: "observe.monitoring.view",
  },
  { value: "trace", label: "链路分析", permission: "observe.monitoring.view" },
  {
    value: "inspection_review",
    label: "巡检复盘",
    permission: "observe.ai.view",
  },
];

export function ProfessionalTask({
  onClose,
  onSubmit,
  pending,
  toolset,
}: {
  onClose: () => void;
  onSubmit: (question: string, intent: WorkbenchTaskIntent) => Promise<boolean>;
  pending: boolean;
  toolset?: WorkbenchSessionToolset;
}) {
  const bootstrap = useAppStore((state) => state.bootstrap);
  const permissions = bootstrap?.permissionSnapshot.permissionKeys ?? [];
  const [form] = Form.useForm<WorkbenchTaskIntent & { question: string }>();
  const selected: Capability[] = Form.useWatch("capabilities", form) ?? [];
  const sourceId: string | undefined = Form.useWatch(
    "performanceDataSourceId",
    form,
  );
  const [failed, setFailed] = useState(false);
  const catalog = useQuery({
    queryKey: ["assistant-catalog", bootstrap?.currentUser.userId],
    queryFn: assistantApi.catalog,
    enabled: permissions.includes("observe.ai.view"),
    retry: false,
  });
  const metrics = useQuery({
    queryKey: ["assistant-metrics", bootstrap?.currentUser.userId, sourceId],
    queryFn: () => assistantApi.metrics(sourceId!),
    enabled:
      selected.includes("performance") &&
      Boolean(sourceId) &&
      permissions.includes("observe.monitoring.view"),
    retry: false,
  });
  const inspections = useQuery({
    queryKey: ["assistant-inspections", bootstrap?.currentUser.userId],
    queryFn: assistantApi.inspections,
    enabled:
      selected.includes("inspection_review") &&
      permissions.includes("observe.ai.view"),
    retry: false,
  });
  const sources = (kind: string) =>
    (catalog.data?.dataSources ?? []).filter(
      (source) =>
        source.enabled &&
        source.sourceKind === kind &&
        source.mcpAdapter === `${kind}.v1` &&
        (!toolset?.enabledAdapterIds?.length ||
          toolset.enabledAdapterIds.includes(source.mcpAdapter)),
    );
  const allowed =
    selected.length > 0 &&
    permissions.includes("ai.gateway.invoke") &&
    selected.every((kind) =>
      permissions.includes(
        capabilities.find((item) => item.value === kind)!.permission,
      ),
    );
  return (
    <Modal
      open
      title="专业分析任务"
      okText="开始分析"
      cancelText="取消"
      width={680}
      onCancel={onClose}
      onOk={() => form.submit()}
      confirmLoading={pending}
      okButtonProps={{
        disabled:
          !allowed ||
          pending ||
          catalog.isError ||
          metrics.isError ||
          inspections.isError,
      }}
      styles={{ body: { maxHeight: "70dvh", overflowY: "auto" } }}
    >
      <Form
        form={form}
        layout="vertical"
        initialValues={{ capabilities: [], minDurationMs: 0 }}
        onFinish={async (values) => {
          if (!allowed || pending) return;
          const intent: WorkbenchTaskIntent = { capabilities: selected };
          if (selected.includes("root_cause"))
            intent.rootCauseProfileId = values.rootCauseProfileId;
          if (selected.includes("performance")) {
            intent.performanceDataSourceId = values.performanceDataSourceId;
            intent.metricKey = values.metricKey;
          }
          if (selected.includes("trace")) {
            intent.traceDataSourceId = values.traceDataSourceId;
            intent.traceId = values.traceId?.trim() || undefined;
            intent.minDurationMs = values.minDurationMs ?? 0;
          }
          if (selected.includes("inspection_review"))
            intent.inspectionRunIds = values.inspectionRunIds;
          const accepted = await onSubmit(values.question.trim(), intent);
          setFailed(!accepted);
          if (accepted) onClose();
        }}
      >
        <Alert
          type="info"
          title="本次任务可组合能力，下一条消息继续普通对话。"
        />
        <Form.Item
          name="capabilities"
          label="任务能力"
          rules={[{ required: true }]}
        >
          <Checkbox.Group
            options={capabilities.map((item) => ({
              ...item,
              disabled:
                !permissions.includes(item.permission) ||
                !permissions.includes("ai.gateway.invoke"),
            }))}
          />
        </Form.Item>
        {selected.includes("root_cause") ? (
          <Form.Item name="rootCauseProfileId" label="根因分析模板">
            <Select
              aria-label="根因分析模板"
              allowClear
              placeholder="使用默认根因策略"
              options={(catalog.data?.analysisProfiles ?? [])
                .filter(
                  (profile) => profile.enabled && profile.mode === "root_cause",
                )
                .map((profile) => ({ value: profile.id, label: profile.name }))}
            />
          </Form.Item>
        ) : null}
        {selected.includes("performance") ? (
          <>
            <Form.Item
              name="performanceDataSourceId"
              label="指标数据源"
              rules={[{ required: true }]}
            >
              <Select
                aria-label="指标数据源"
                options={sources("metrics").map((source) => ({
                  value: source.id,
                  label: source.name,
                }))}
                onChange={() => form.setFieldValue("metricKey", undefined)}
              />
            </Form.Item>
            <Form.Item
              name="metricKey"
              label="性能指标"
              rules={[{ required: true }]}
            >
              <Select
                aria-label="性能指标"
                loading={metrics.isFetching}
                options={(metrics.data ?? []).map((metric) => ({
                  value: metric.key,
                  label: metric.label,
                  disabled: !metric.available,
                }))}
              />
            </Form.Item>
          </>
        ) : null}
        {selected.includes("trace") ? (
          <>
            <Form.Item
              name="traceDataSourceId"
              label="链路数据源"
              rules={[{ required: true }]}
            >
              <Select
                aria-label="链路数据源"
                options={sources("traces").map((source) => ({
                  value: source.id,
                  label: source.name,
                }))}
              />
            </Form.Item>
            <Form.Item name="traceId" label="Trace ID">
              <Input aria-label="Trace ID" maxLength={256} />
            </Form.Item>
            <Form.Item
              name="minDurationMs"
              label="最短耗时（毫秒，0 表示不过滤）"
            >
              <InputNumber
                aria-label="链路最短耗时"
                min={0}
                max={86400000}
                precision={0}
              />
            </Form.Item>
          </>
        ) : null}
        {selected.includes("inspection_review") ? (
          <Form.Item
            name="inspectionRunIds"
            label="巡检执行记录"
            rules={[{ required: true, type: "array", min: 1, max: 20 }]}
          >
            <Select
              aria-label="巡检执行记录"
              mode="multiple"
              maxCount={20}
              loading={inspections.isFetching}
              options={(inspections.data ?? [])
                .filter((run) => run.status === "completed" && run.completedAt)
                .map((run) => ({
                  value: run.id,
                  label: run.summary || run.id,
                }))}
            />
          </Form.Item>
        ) : null}
        <Form.Item
          name="question"
          label="分析目标"
          rules={[{ required: true, whitespace: true }]}
        >
          <Input.TextArea
            aria-label="分析目标"
            maxLength={16384}
            autoSize={{ minRows: 3, maxRows: 6 }}
          />
        </Form.Item>
        {catalog.isError || metrics.isError || inspections.isError ? (
          <Alert type="error" title="分析输入读取失败，请重新打开重试。" />
        ) : null}
        {failed ? (
          <Alert
            type="error"
            title="任务提交未确认，输入已保留；请先核对任务列表。"
          />
        ) : null}
      </Form>
    </Modal>
  );
}
