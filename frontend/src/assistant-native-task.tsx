import { useEffect, useState } from "react";
import { Alert, Button, Input, Typography } from "antd";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import type { WorkbenchAgentRun } from "@opensoha/contracts/gen/ts/sohaapi";
import { assistantApi } from "@/assistant-api";
import { selectAssistantOwner, useAppStore } from "@/store";
import { VMSSHCommandProgress } from "@/assistant-vm-access";

const phases: Record<string, string> = {
  waiting_approval: "等待变更审批",
  waiting_task: "等待领域执行与验收",
  cancelling: "取消处理中，等待执行端确认",
};

export function NativeTaskProgress({ run }: { run: WorkbenchAgentRun }) {
  const owner = useAppStore(selectAssistantOwner);
  const client = useQueryClient();
  const [cursor, setCursor] = useState(0);
  const [replies, setReplies] = useState<Record<string, string>>({});
  const [input, setInput] = useState("");
  const active = ["queued", "running"].includes(run.status);
  const canConnectVM = useAppStore((state) =>
    state.bootstrap?.permissionSnapshot.permissionKeys.includes("virtualization.vms.connect") &&
    state.bootstrap.permissionSnapshot.permissionKeys.includes("secret.use"),
  );
  const capabilityTaskID = typeof run.output?.capabilityTaskId === "string" ? run.output.capabilityTaskId : "";
  const capabilityTask = useQuery({
    queryKey: ["assistant-capability-task", owner, run.id, capabilityTaskID],
    queryFn: ({ signal }) => assistantApi.capabilityTask(capabilityTaskID, signal),
    enabled: Boolean(canConnectVM && capabilityTaskID),
    refetchInterval: active ? 2000 : false,
    retry: false,
  });
  const waitingInput =
    active && run.phase === "paused" && run.stopReason === "waiting_input";
  const events = useQuery({
    queryKey: ["assistant-native-events", owner, run.id, cursor],
    queryFn: async ({ signal }) => ({
      afterSequence: cursor,
      page: await assistantApi.events(run.id, cursor, signal),
    }),
    enabled: active,
    refetchInterval: 2000,
    retry: false,
  });
  const resume = useMutation({
    mutationFn: () => assistantApi.resume(run.id, { input: input.trim() }),
    onSuccess: (updated) => {
      setInput("");
      client.setQueryData<WorkbenchAgentRun[]>(
        ["assistant-tasks", owner],
        (runs) =>
          runs?.map((item) => (item.id === updated.id ? updated : item)),
      );
    },
    onSettled: () =>
      client.invalidateQueries({ queryKey: ["assistant-tasks", owner] }),
  });
  useEffect(() => {
    if (!active)
      void client.invalidateQueries({
        queryKey: ["assistant-messages", owner, run.sessionId],
      });
  }, [active, client, owner, run.sessionId]);
  useEffect(() => {
    const data = events.data;
    if (!data || data.afterSequence !== cursor) return;
    if (data.page.resyncRequired) {
      setReplies({});
      setCursor(0);
      void client.invalidateQueries({
        queryKey: ["assistant-messages", owner, run.sessionId],
      });
      return;
    }
    setReplies((previous) => {
      const next = { ...previous };
      for (const event of data.page.items) {
        if (
          event.sessionId !== run.sessionId ||
          event.runId !== run.id ||
          event.sequence <= cursor ||
          typeof event.messageId !== "string"
        )
          continue;
        if (
          event.type === "message.delta" &&
          typeof event.contentDelta === "string"
        )
          next[event.messageId] = (
            (next[event.messageId] || "") + event.contentDelta
          ).slice(0, 16384);
        if (event.type === "message.done" && typeof event.content === "string")
          next[event.messageId] = event.content.slice(0, 16384);
      }
      // ponytail: only recent visible text; durable history remains on the server.
      return Object.fromEntries(Object.entries(next).slice(-16));
    });
    setCursor(data.page.nextSequence);
  }, [events.data, cursor, client, owner, run.id, run.sessionId]);
  return (
    <div className="app-assistant-native-progress" aria-label="原生任务进度">
      {phases[run.phase || ""] ? (
        <Typography.Paragraph>{phases[run.phase || ""]}</Typography.Paragraph>
      ) : null}
      {events.isError ? (
        <Button onClick={() => void events.refetch()}>
          进度读取失败，重试
        </Button>
      ) : null}
      <div aria-live="polite">
        {Object.entries(replies).map(([id, text]) => (
          <Typography.Paragraph key={id}>{text}</Typography.Paragraph>
        ))}
      </div>
      {canConnectVM && capabilityTask.data?.nodes.map((node) =>
        node.invocation?.task?.kind === "virtualization.ssh_command" ? (
          <VMSSHCommandProgress key={node.invocation.task.id} commandID={node.invocation.task.id} />
        ) : null,
      )}
      {canConnectVM && capabilityTask.isError ? <Alert type="error" title="领域任务读取失败" action={<Button onClick={() => void capabilityTask.refetch()}>重试</Button>} /> : null}
      {waitingInput ? (
        <>
          <Typography.Paragraph>
            {typeof run.output?.pendingQuestion === "string"
              ? run.output.pendingQuestion
              : "请补充任务所需信息。"}
          </Typography.Paragraph>
          <Input.TextArea
            aria-label={`任务 ${run.id} 的补充信息`}
            value={input}
            maxLength={16384}
            onChange={(event) => setInput(event.target.value)}
          />
          <Button
            loading={resume.isPending}
            disabled={!input.trim() || resume.isPending}
            onClick={() => resume.mutate()}
          >
            补充并继续
          </Button>
        </>
      ) : null}
      {resume.isError ? (
        <Alert
          type="error"
          title="续接未确认，请核对最新任务状态；补充内容已保留。"
        />
      ) : null}
    </div>
  );
}
