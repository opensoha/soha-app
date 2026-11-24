import { Alert, Button, Space, Spin, Typography } from "antd";
import { useMutation, useQuery } from "@tanstack/react-query";
import { getBootstrap, restoreSession } from "@/api";
import { getHostState, openMeshInboxWindow } from "@/native/host";
import { selectAssistantOwner, useAppStore } from "@/store";
import { meshApi } from "./assistant-mesh-api";

export function MeshCompanion() {
  const owner = useAppStore(selectAssistantOwner);
  const userId = useAppStore((state) => state.bootstrap?.currentUser.userId);
  const session = useQuery({
    queryKey: ["mesh-companion-session"],
    queryFn: async () => {
      const store = useAppStore.getState();
      store.setHost(await getHostState());
      const restored = await restoreSession();
      if (!restored) return false;
      store.commitSession(restored, await getBootstrap());
      return true;
    },
    retry: false,
  });
  const inbox = useQuery({
    queryKey: ["mesh-companion-inbox", owner],
    queryFn: () => meshApi.inquiries("inbox"),
    enabled: session.data === true && Boolean(owner && userId),
    refetchInterval: 8_000,
    retry: false,
  });
  const open = useMutation({ mutationFn: openMeshInboxWindow, retry: false });
  const pending = inbox.isSuccess && inbox.data.some(
    (item) => item.ownerId === userId && item.status === "pending",
  );
  return (
    <main aria-label="助手互联待办" style={{ padding: 16 }}>
      <Space orientation="vertical" size="small">
        <Typography.Text strong>助手互联</Typography.Text>
        {session.isPending || (session.data && inbox.isPending) ? <Spin size="small" /> : null}
        {session.isError ? <Alert type="error" title="无法连接到 Soha" /> : null}
        {session.data === false ? <Typography.Text>请在 App 主窗口登录。</Typography.Text> : null}
        {inbox.isError ? <Typography.Text>待办暂不可用。</Typography.Text> : null}
        {pending ? (
          <>
            <Typography.Text>有一项待办需要你处理。</Typography.Text>
            <Button type="primary" onClick={() => open.mutate()} loading={open.isPending}>打开待办</Button>
          </>
        ) : inbox.isSuccess ? <Typography.Text type="secondary">暂无待处理问询</Typography.Text> : null}
        {open.isError ? <Alert type="error" title="主窗口暂不可用，请从托盘打开" /> : null}
      </Space>
    </main>
  );
}
