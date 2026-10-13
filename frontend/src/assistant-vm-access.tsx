import { Alert, Button, Space, Typography } from "antd";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { assistantApi } from "@/assistant-api";
import { selectAssistantOwner, useAppStore } from "@/store";

export function VMSSHCommandProgress({ commandID }: { commandID: string }) {
  const owner = useAppStore(selectAssistantOwner);
  const client = useQueryClient();
  const canView = useAppStore((state) => state.bootstrap?.permissionSnapshot.permissionKeys.includes("virtualization.vms.view") ?? false);
  const command = useQuery({
    queryKey: ["assistant-vm-command", owner, commandID],
    queryFn: ({ signal }) => assistantApi.vmSSHCommand(commandID, signal),
    retry: false,
    refetchInterval: (query) => query.state.data?.terminal ? false : 2000,
  });
  const vmID = command.data?.vmId ?? "";
  const binding = useQuery({
    queryKey: ["assistant-vm-binding", owner, vmID],
    queryFn: ({ signal }) => assistantApi.vmAccessBinding(vmID, signal),
    enabled: Boolean(vmID) && canView,
    retry: false,
  });
  const cancel = useMutation({
    mutationFn: () => assistantApi.cancelVMSSHCommand(commandID),
    retry: false,
    onSuccess: (receipt) => client.setQueryData(["assistant-vm-command", owner, commandID], receipt),
    onSettled: () => client.invalidateQueries({ queryKey: ["assistant-capability-task", owner] }),
  });
  if (command.isError) return <Alert type="error" title="SSH 回执读取失败" action={<Button onClick={() => void command.refetch()}>重试</Button>} />;
  if (!command.data) return <Typography.Paragraph>正在读取 SSH 原任务回执…</Typography.Paragraph>;
  const receipt = command.data;
  return <Space orientation="vertical" style={{ width: "100%" }} aria-label="VM SSH 执行回执">
    <Typography.Text strong>VM {receipt.vmId} · 原任务 {receipt.id} · {receipt.status}</Typography.Text>
    {binding.data ? <Typography.Text>账号 {binding.data.username} · 凭证 {binding.data.credentialRef} · 原绑定版本 {receipt.bindingRevision} / 当前 {binding.data.revision}</Typography.Text> : null}
    {binding.isError ? <Alert type="warning" title="当前登录绑定不可读取；原执行回执仍保留。" /> : null}
    <Alert type={receipt.outcome === "succeeded" ? "success" : receipt.outcome === "unknown" ? "warning" : "info"} title={receipt.outcome === "unknown" ? "执行副作用尚未确认；不会自动重跑。" : `执行结果：${receipt.outcome}，退出码 ${receipt.exitCode ?? "未确认"}`} description="SSH 命令回执仅证明这次执行。个人电脑的文件、浏览器和完整就绪能力由服务端单独验收。" />
    {receipt.stdout ? <pre style={{ whiteSpace: "pre-wrap", maxHeight: 240, overflow: "auto" }} aria-label="SSH 标准输出">{receipt.stdout}</pre> : null}
    {receipt.stderr ? <pre style={{ whiteSpace: "pre-wrap", maxHeight: 160, overflow: "auto" }} aria-label="SSH 错误输出">{receipt.stderr}</pre> : null}
    {receipt.outputTruncated ? <Typography.Text type="warning">输出超过上限，已截断。</Typography.Text> : null}
    {!receipt.terminal ? <Button loading={cancel.isPending} onClick={() => cancel.mutate()}>取消原 SSH 任务</Button> : null}
    {cancel.isError ? <Alert type="error" title="取消未确认，请刷新原回执后重试。" /> : null}
  </Space>;
}
