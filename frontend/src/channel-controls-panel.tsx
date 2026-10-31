import { Alert, Descriptions, Space, Tag, Typography } from "antd";
import { useQuery } from "@tanstack/react-query";
import { getNetworkStatus } from "@/native/host";
import { useAppStore } from "@/store";

export function ChannelControlsPanel() {
  const host = useAppStore((s) => s.host);
  const user = useAppStore((s) => s.session?.user.userId);
  const chinese = useAppStore((s) => s.locale) === "zh_CN";
  const text = (zh: string, en: string) => (chinese ? zh : en);
  const label = (value: string) =>
    channelLabels[value]?.[chinese ? 0 : 1] ?? value;
  const supported = host?.app.platform === "windows";
  const query = useQuery({
    queryKey: ["native-channel-controls", host?.serverUrl, user],
    queryFn: getNetworkStatus,
    enabled: supported && Boolean(user),
    gcTime: 0,
    retry: false,
    refetchInterval: 5000,
  });
  const status = query.isSuccess ? query.data.channelControls : undefined;
  return (
    <Space orientation="vertical" size={12} style={{ width: "100%" }}>
      <Typography.Text strong>
        {text("端点通道保护", "Endpoint channel protection")}
      </Typography.Text>
      {!supported ? (
        <Alert
          type="info"
          title={text(
            "此平台原生 USB、打印和剪贴板控制尚不支持",
            "Native USB, print and clipboard controls are unsupported on this platform",
          )}
        />
      ) : null}
      {query.isError ? (
        <Alert
          type="warning"
          title={text(
            "保护服务状态不可读",
            "Protection service status unavailable",
          )}
          description={query.error.message}
        />
      ) : null}
      {supported && !status ? (
        <Typography.Text>
          {text(
            "尚未取得当前保护服务状态；不能视为已保护",
            "No current protection service status; protection is not established",
          )}
        </Typography.Text>
      ) : null}
      {status ? (
        <>
          <Alert
            type={
              status.policyFresh && status.controlReachable ? "info" : "warning"
            }
            title={`${text("策略版本", "Policy version")} ${status.policyVersion}`}
            description={text(
              "由受信任原生服务执行，关闭 VPN 不会解除。策略失联或过期时保留原限制；解除由管理员发布更高版本。",
              "Enforced by the trusted native service, independently of VPN. Controls remain on control loss or expiry. An administrator publishes a higher version to release them.",
            )}
          />
          <Typography.Text type="secondary">
            {status.policyFresh
              ? text("策略有效期内", "Policy is current")
              : text(
                  "策略未确认或已过期",
                  "Policy unconfirmed or expired",
                )}{" "}
            ·{" "}
            {status.controlReachable
              ? text("控制面可达", "Control plane reachable")
              : text("控制面不可达", "Control plane unreachable")}{" "}
            · {label(status.diagnostic)} · {status.lastObservedAt}
          </Typography.Text>
          <Descriptions
            size="small"
            column={1}
            items={status.channels.map((c) => ({
              key: c.name,
              label: label(c.name),
              children: (
                <Space orientation="vertical" size={4}>
                  <Tag
                    color={
                      c.state === "failed" || c.state === "conflict"
                        ? "error"
                        : c.state === "partial" || c.state === "unsupported"
                          ? "warning"
                          : "default"
                    }
                  >
                    {label(c.state)}
                  </Tag>
                  <span>
                    {label(c.scope)} ·{" "}
                    {text("控制数 / 目标数", "Controlled / targets")}:{" "}
                    {c.controlled}/{c.targets}
                  </span>
                  <span title={c.reasonCode}>{label(c.reasonCode)}</span>
                </Space>
              ),
            }))}
          />
        </>
      ) : null}
      <Typography.Paragraph type="secondary">
        {text(
          "覆盖当前可锁定 USB 卷、本机队列新任务和登记用户控制台的 Win32 剪贴板访问。忙碌/未知目标、既有打印句柄、热插拔间隙、远程打印、剪贴板历史/云同步和其他会话不作阻断承诺。不会读取或上传剪贴板正文。",
          "Covers currently lockable USB volumes, new jobs on local queues and Win32 clipboard access in the enrolled console. Busy/unknown targets, existing print handles, hotplug gaps, remote printing, clipboard history/cloud sync and other sessions have no blocking claim. Clipboard bodies are not read or uploaded.",
        )}
      </Typography.Paragraph>
    </Space>
  );
}

const channelLabels: Record<string, [string, string]> = {
  usb: ["USB 存储卷", "USB storage volumes"],
  print: ["打印", "Printing"],
  clipboard: ["剪贴板", "Clipboard"],
  current_usb_volumes: ["当前 USB 卷", "Current USB volumes"],
  local_new_print_jobs: ["本机队列新任务", "New jobs on local queues"],
  enrolled_console_win32: [
    "登记用户控制台 Win32 访问",
    "Enrolled console Win32 access",
  ],
  off: ["限制已解除", "Restrictions released"],
  unconfigured: ["尚未发布策略", "No policy published"],
  not_present: ["当前无适用目标", "No current applicable targets"],
  controlled: ["已施加范围内控制", "Scoped controls applied"],
  partial: ["部分目标未受控", "Some targets uncontrolled"],
  failed: ["执行失败", "Execution failed"],
  unsupported: ["不支持", "Unsupported"],
  conflict: ["恢复冲突，需处理", "Restoration conflict"],
  disabled: ["该通道限制已关闭", "Channel restriction disabled"],
  native_scope_only: [
    "仅适用于声明的原生范围",
    "Applies only to the declared native scope",
  ],
  not_published: ["管理员尚未发布策略", "No administrator policy published"],
  volume_close_failed: ["USB 卷锁释放未确认", "USB volume unlock unconfirmed"],
  volume_inventory_failed: ["无法枚举存储卷", "Volume inventory unavailable"],
  native_deadline: ["本轮协调超时", "Reconciliation deadline reached"],
  volume_readback_unknown: [
    "现有卷锁身份读回不明",
    "Locked volume identity unconfirmed",
  ],
  volume_identity_unknown: [
    "存储卷身份无法确认",
    "Volume identity unconfirmed",
  ],
  volume_access_denied: ["无权锁定 USB 卷", "USB volume lock access denied"],
  volume_busy_or_unsupported: [
    "USB 卷忙碌或不支持锁定",
    "USB volume busy or lock unsupported",
  ],
  no_current_usb_volumes: ["当前未发现 USB 卷", "No current USB volumes"],
  printer_inventory_failed: [
    "无法读取本机打印队列",
    "Local print queue inventory unavailable",
  ],
  printer_restore_pending: [
    "打印权限恢复尚未完成",
    "Printer permissions need restoration",
  ],
  printer_acl_unconfirmed: [
    "打印权限修改未确认",
    "Printer permission change unconfirmed",
  ],
  no_local_print_queues: ["当前无本机打印队列", "No local print queues"],
  clipboard_cleanup_failed: [
    "剪贴板守护进程退出未确认",
    "Clipboard guard exit unconfirmed",
  ],
  clipboard_guard_unavailable: [
    "无法建立登记会话的剪贴板控制",
    "Enrolled-session clipboard guard unavailable",
  ],
  waiting_for_control: ["等待控制面", "Waiting for control plane"],
  control_or_policy_unavailable: [
    "控制面或策略不可用，保留原限制",
    "Control or policy unavailable; prior controls retained",
  ],
  receipt_unconfirmed: ["回执提交未确认", "Receipt submission unconfirmed"],
};
