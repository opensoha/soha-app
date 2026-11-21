import { useEffect, useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import {
  Alert,
  Button,
  Checkbox,
  Drawer,
  Empty,
  Input,
  InputNumber,
  List,
  Select,
  Space,
  Spin,
  Tabs,
  Tag,
  Typography,
} from "antd";
import { ApiError } from "@/api";
import { AssistantMeshDelegations } from "@/assistant-mesh-delegations";
import {
  meshApi,
  type MeshAsset,
  type MeshAssetInput,
  type MeshAssetKind,
  type MeshAudience,
  type MeshInquiry,
  type MeshInquiryInput,
  type MeshShareReply,
} from "@/assistant-mesh-api";

type MeshTab = "find" | "inbox" | "assets" | "profile" | "sent" | "delegations";
type Visibility = MeshAudience["visibility"];

const INQUIRY_STATUS: Record<MeshInquiry["status"], string> = {
  answered: "已自动答复",
  processing: "正在查找可见资料",
  pending: "已转交本人",
  replied: "同事已回复",
  expired: "已过期",
  invalidated: "已失效",
};
const KIND_LABEL: Record<MeshAssetKind, string> = {
  skill: "Skill",
  experience_card: "经验卡",
  work_pulse: "工作进度",
};
const WORK_STATUS = [
  { value: "in_progress", label: "进行中" },
  { value: "blocked", label: "阻塞" },
  { value: "done", label: "已完成" },
];

function errorText(error: unknown) {
  return error instanceof Error && error.message ? error.message : "请求失败，请稍后重试";
}

function retryable(error: unknown) {
  return error instanceof ApiError && error.status >= 500;
}

function denied(error: unknown) {
  return error instanceof ApiError && (error.status === 401 || error.status === 403);
}

function observedAt(value: string) {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString("zh-CN");
}

function audienceValid(visibility: Visibility, teams: string[], projects: string[]) {
  return visibility !== "teams" || teams.length > 0
    ? visibility !== "projects" || projects.length > 0
    : false;
}

function lifetimeValid(kind: "experience_card" | "work_pulse", value: number) {
  return kind === "work_pulse" ? value >= 1 && value <= 336 : value >= 1 && value <= 3650;
}

function showStatus(inquiry: MeshInquiry) {
  return ["processing", "pending", "expired", "invalidated"].includes(inquiry.status);
}

export function AssistantMeshPanel({
  owner,
  userId,
  teams,
  projects,
  sessionId,
  open,
  onClose,
  onPendingCount,
  onRunStarted,
  initial,
}: {
  owner: string;
  userId: string;
  teams: string[];
  projects: string[];
  sessionId?: string;
  open: boolean;
  onClose: () => void;
  onPendingCount?: (count: number) => void;
  onRunStarted?: (runId: string) => void;
  initial?: {
    key: number;
    tab: MeshTab;
    query?: string;
    question?: string;
    workspaceSummary?: string;
    source?: { messageIds?: string[]; runId?: string };
  };
}) {
  const profileQuery = useQuery({
    queryKey: ["assistant-mesh-panel", owner, "profile"],
    queryFn: meshApi.profile,
    enabled: Boolean(owner),
    retry: false,
    staleTime: 0,
    refetchInterval: open ? 10_000 : false,
  });
  const authorized = profileQuery.isSuccess;
  const [tab, setTab] = useState<MeshTab>(initial?.tab ?? "find");
  const [search, setSearch] = useState(initial?.query ?? "");
  const [term, setTerm] = useState(initial?.query ?? "");
  const [selectedAssistant, setSelectedAssistant] = useState<string>();
  const [question, setQuestion] = useState(initial?.question ?? "");
  const [preview, setPreview] = useState<{ question: string; blocked: boolean }>();
  const [previewFor, setPreviewFor] = useState("");
  const [receiptId, setReceiptId] = useState<string>();
  const [profileOpen, setProfileOpen] = useState(false);
  const [profileAway, setProfileAway] = useState(false);
  const [profileIntro, setProfileIntro] = useState("");
  const [replyFor, setReplyFor] = useState("");
  const [replyText, setReplyText] = useState("");
  const [share, setShare] = useState(false);
  const [shareKind, setShareKind] = useState<"experience_card" | "work_pulse">("experience_card");
  const [shareTitle, setShareTitle] = useState("");
  const [shareSummary, setShareSummary] = useState("");
  const [shareVisibility, setShareVisibility] = useState<Visibility>(teams.length ? "teams" : projects.length ? "projects" : "organization");
  const [shareTeams, setShareTeams] = useState<string[]>([]);
  const [shareProjects, setShareProjects] = useState<string[]>([]);
  const [shareLifetime, setShareLifetime] = useState(24);
  const [shareStatus, setShareStatus] = useState("in_progress");
  const [assetKind, setAssetKind] = useState<MeshAssetKind>("skill");
  const [assetTitle, setAssetTitle] = useState("");
  const [assetBody, setAssetBody] = useState("");
  const [applicability, setApplicability] = useState("");
  const [workStatus, setWorkStatus] = useState("in_progress");
  const [blockerReason, setBlockerReason] = useState("");
  const [asset, setAsset] = useState<MeshAsset>();
  const [prompt, setPrompt] = useState("");
  const [assetNotice, setAssetNotice] = useState("");
  const [assetVisibility, setAssetVisibility] = useState<Visibility>("private");
  const [assetTeams, setAssetTeams] = useState<string[]>([]);
  const [assetProjects, setAssetProjects] = useState<string[]>([]);
  const [assetLifetime, setAssetLifetime] = useState(90);

  const searchQuery = useQuery({
    queryKey: ["assistant-mesh-panel", owner, "search", term],
    queryFn: () => meshApi.search(term.trim() || undefined),
    enabled: open && authorized && tab === "find",
    retry: false,
    staleTime: 30_000,
  });
  const inboxQuery = useQuery({
    queryKey: ["assistant-mesh-panel", owner, "inbox"],
    queryFn: () => meshApi.inquiries("inbox"),
    enabled: Boolean(owner) && authorized,
    retry: false,
    staleTime: 0,
    refetchInterval: open ? 7_000 : false,
  });
  const sentQuery = useQuery({
    queryKey: ["assistant-mesh-panel", owner, "sent"],
    queryFn: () => meshApi.inquiries("sent"),
    enabled: open && authorized && (tab === "sent" || Boolean(receiptId)),
    retry: false,
    staleTime: 0,
    refetchInterval: open ? 7_000 : false,
  });
  const inbox = inboxQuery.isSuccess
    ? inboxQuery.data.filter((item) => item.ownerId === userId && item.status === "pending")
    : [];
  const sent = sentQuery.isSuccess
    ? sentQuery.data.filter((item) => item.callerId === userId)
    : [];
  const assistants = searchQuery.isSuccess ? searchQuery.data : [];
  const receipt = sent.find((item) => item.id === receiptId);

  useEffect(() => {
    onPendingCount?.(inbox.length);
  }, [inbox.length, onPendingCount]);

  useEffect(() => {
    if (profileQuery.data) {
      setProfileOpen(profileQuery.data.open);
      setProfileAway(profileQuery.data.away);
      setProfileIntro(profileQuery.data.intro);
    }
  }, [profileQuery.data]);

  useEffect(() => {
    setAsset(undefined);
    setAssetNotice("");
    setReplyFor("");
    setReplyText("");
    setShare(false);
    setSearch("");
    setTerm("");
    setQuestion("");
    setSelectedAssistant(undefined);
    setPreview(undefined);
    setPreviewFor("");
    setReceiptId(undefined);
  }, [owner]);

  useEffect(() => {
    if (!open || !initial) return;
    setTab(initial.tab);
    setSearch(initial.query ?? "");
    setTerm(initial.query ?? "");
    setQuestion(initial.question ?? "");
    setSelectedAssistant(undefined);
    setPreview(undefined);
    setPreviewFor("");
    setReceiptId(undefined);
    setReplyFor("");
    setAsset(undefined);
    setAssetNotice("");
    if (initial.workspaceSummary) {
      setAssetKind("work_pulse");
      setAssetTitle("工作区进展");
      setAssetBody(initial.workspaceSummary);
      setAssetLifetime(24);
    }
  }, [open, initial]);

  useEffect(() => {
    if (!profileQuery.isError) return;
    setQuestion("");
    setSelectedAssistant(undefined);
    setPreview(undefined);
    setPreviewFor("");
    setReceiptId(undefined);
    setReplyFor("");
    setReplyText("");
    setAsset(undefined);
    setAssetNotice("");
  }, [profileQuery.isError]);

  const previewMutation = useMutation({
    mutationFn: (value: string) => meshApi.preview(value),
    onSuccess: (value, input) => {
      setPreview(value);
      setPreviewFor(input);
    },
  });
  const sendMutation = useMutation({
    mutationFn: (input: MeshInquiryInput) => meshApi.ask(input),
    retry: (count, error) => count < 2 && retryable(error),
    onSuccess: (item) => {
      setReceiptId(item.id);
      setPreview(undefined);
      setPreviewFor("");
      setQuestion("");
    },
  });
  const replyMutation = useMutation({
    mutationFn: (input: { id: string; answer: string }) => meshApi.reply(input.id, input.answer),
    onSuccess: () => {
      setReplyFor("");
      setReplyText("");
      void inboxQuery.refetch();
    },
  });
  const shareMutation = useMutation({
    mutationFn: (input: { id: string; value: MeshShareReply }) => meshApi.replyAndPublish(input.id, input.value),
    onSuccess: () => {
      setReplyFor("");
      setReplyText("");
      setShare(false);
      void inboxQuery.refetch();
    },
  });
  const profileMutation = useMutation({
    mutationFn: () => meshApi.setProfile({ open: profileOpen, away: profileAway, intro: profileIntro }),
  });
  const createMutation = useMutation({
    mutationFn: (input: MeshAssetInput) => meshApi.create(input),
    onSuccess: (created) => {
      loadAsset(created);
      setAssetNotice("草稿已创建；请核对内容、保存摘要后再试跑或发布。");
    },
  });
  const extractMutation = useMutation({
    mutationFn: () => {
      const source = initial?.source;
      if (!sessionId || !source || (!source.runId && !source.messageIds?.length)) {
        throw new Error("请从已选择的会话消息或已完成 Run 发起提炼");
      }
      return meshApi.draft({
        sessionId,
        title: assetTitle.trim(),
        kind: assetKind === "work_pulse" ? "experience_card" : assetKind,
        ...(source.messageIds?.length ? { messageIds: source.messageIds } : { runId: source.runId! }),
      });
    },
    onSuccess: (created) => {
      loadAsset(created);
      setAssetNotice("已按选中来源生成草稿；请编辑并保存后再试跑或发布。");
    },
  });
  const saveMutation = useMutation({
    mutationFn: () => {
      if (!asset?.draftDigest) throw new Error("缺少当前草稿摘要，请先刷新资产");
      return meshApi.updateAsset(asset.id, asset.draftDigest, assetInput());
    },
    onSuccess: (updated) => {
      loadAsset(updated);
      setAssetNotice("草稿已保存；内容变化后需要重新试跑。");
    },
  });
  const trialMutation = useMutation({
    mutationFn: () => {
      if (!asset?.draftDigest) throw new Error("缺少当前草稿摘要，请先刷新资产");
      if (!sessionId || !prompt.trim()) throw new Error("试跑需要当前会话和提示词");
      return meshApi.assetAction(asset.id, "trial", {
        expectedDigest: asset.draftDigest,
        sessionId,
        requestId: crypto.randomUUID(),
        prompt: prompt.trim(),
      });
    },
    onSuccess: (result) => {
      if (result.asset) setAsset(result.asset);
      setAssetNotice(result.runId ? `已返回试跑 Run ${result.runId}` : "试跑请求已提交，但未返回 Run ID；请核对原资产状态");
      if (result.runId) onRunStarted?.(result.runId);
    },
  });
  const publishMutation = useMutation({
    mutationFn: () => {
      if (!asset?.draftDigest) throw new Error("缺少当前草稿摘要，请先刷新资产");
      return meshApi.assetAction(asset.id, "publish", {
        expectedDigest: asset.draftDigest,
        audience: assetAudience(),
        ...(asset.kind === "work_pulse"
          ? { lifetimeHours: assetLifetime }
          : asset.kind === "experience_card"
            ? { lifetimeDays: assetLifetime }
            : {}),
      });
    },
    onSuccess: (result) => {
      if (result.asset) setAsset(result.asset);
      const review = result.asset?.review?.status;
      if (review === "pending") setAssetNotice("发布申请审批中；通过前该版本仅你可见。");
      else if (review === "rejected") setAssetNotice("发布申请已驳回，请修正后重新提交。");
      else if (result.asset?.published) setAssetNotice(`服务端已发布 v${result.asset.published.version}`);
      else setAssetNotice("服务端未返回已发布版本；结果未确认，请刷新核对。");
    },
  });
  const refreshMutation = useMutation({
    mutationFn: () => {
      if (!asset) throw new Error("未选择资产");
      return meshApi.getAsset(asset.id);
    },
    onSuccess: (refreshed) => {
      loadAsset(refreshed);
      setAssetNotice("已读取服务端最新资产状态。");
    },
  });

  function assetInput(): MeshAssetInput {
    return {
      kind: assetKind,
      title: assetTitle.trim(),
      body: assetBody.trim(),
      ...(applicability.trim() ? { applicability: applicability.trim() } : {}),
      ...(assetKind === "work_pulse"
        ? { workStatus, ...(blockerReason.trim() ? { blockerReason: blockerReason.trim() } : {}) }
        : {}),
    };
  }

  function assetAudience(): MeshAudience {
    return {
      visibility: assetVisibility,
      teams: assetVisibility === "teams" ? assetTeams : undefined,
      projects: assetVisibility === "projects" ? assetProjects : undefined,
    };
  }

  function loadAsset(next: MeshAsset) {
    setAsset(next);
    setAssetKind(next.kind === "mcp" ? "skill" : next.kind);
    const input = next.draft ?? next.published?.input;
    setAssetTitle(input?.title ?? "");
    setAssetBody(input?.body ?? "");
    setApplicability(input?.applicability ?? "");
    setWorkStatus(input?.workStatus ?? "in_progress");
    setBlockerReason(input?.blockerReason ?? "");
  }

  function editQuestion(value: string) {
    setQuestion(value);
    setPreview(undefined);
    setPreviewFor("");
    setReceiptId(undefined);
    if (!retryable(sendMutation.error)) sendMutation.reset();
  }

  function previewQuestion() {
    const value = question.trim();
    if (!selectedAssistant || !value || previewMutation.isPending) return;
    previewMutation.mutate(value);
  }

  function confirmSend() {
    if (!selectedAssistant || !preview || preview.blocked || previewFor !== question.trim()) return;
    if (sendMutation.isPending || sendMutation.isError) return;
    sendMutation.mutate({
      ownerId: selectedAssistant,
      requestId: crypto.randomUUID(),
      question: preview.question,
    });
  }

  function openReply(inquiry: MeshInquiry) {
    setReplyFor(inquiry.id);
    setReplyText("");
    setShare(false);
    setShareTitle("");
    setShareSummary("");
  }

  function confirmShare(inquiry: MeshInquiry) {
    const answer = replyText.trim();
    if (!answer || !shareTitle.trim() || !shareSummary.trim()) return;
    if (!audienceValid(shareVisibility, shareTeams, shareProjects)) return;
    if (!lifetimeValid(shareKind, shareLifetime)) return;
    shareMutation.mutate({
      id: inquiry.id,
      value: {
        answer,
        title: shareTitle.trim(),
        summary: shareSummary.trim(),
        kind: shareKind,
        audience: {
          visibility: shareVisibility,
          teams: shareVisibility === "teams" ? shareTeams : undefined,
          projects: shareVisibility === "projects" ? shareProjects : undefined,
        },
        ...(shareKind === "work_pulse" ? { lifetimeHours: shareLifetime, workStatus: shareStatus } : { lifetimeDays: shareLifetime }),
      },
    });
  }

  const source = initial?.source;
  const hasSource = Boolean(sessionId && source && (source.runId || source.messageIds?.length));
  const busyAsset =
    createMutation.isPending || extractMutation.isPending || saveMutation.isPending || trialMutation.isPending || publishMutation.isPending;
  const assetLifetimeValid = asset?.kind === "work_pulse" || asset?.kind === "experience_card"
    ? lifetimeValid(asset.kind, assetLifetime)
    : true;

  const findPane = (
    <Space orientation="vertical" size={14} style={{ width: "100%" }}>
      <Input.Search
        aria-label="按姓名或公开主题查找助手"
        value={search}
        allowClear
        enterButton="查找"
        placeholder="按姓名或公开主题查找助手"
        loading={searchQuery.isFetching}
        onChange={(event) => setSearch(event.target.value)}
        onSearch={(value) => setTerm(value)}
      />
      {searchQuery.isError ? (
        <Alert type={denied(searchQuery.error) ? "warning" : "error"} showIcon title={denied(searchQuery.error) ? "没有查找同事助手的权限" : "助手列表读取失败"} description={denied(searchQuery.error) ? undefined : errorText(searchQuery.error)} />
      ) : searchQuery.isPending ? (
        <Spin />
      ) : assistants.length === 0 ? (
        <Empty description="没有匹配的同事助手" />
      ) : (
        <List
          dataSource={assistants}
          renderItem={(assistant) => (
            <List.Item>
              <Button
                type="text"
                block
                aria-pressed={selectedAssistant === assistant.ownerId}
                style={{ height: "auto", padding: 12, textAlign: "left", whiteSpace: "normal" }}
                onClick={() => {
                  setSelectedAssistant(assistant.ownerId);
                  setPreview(undefined);
                  setPreviewFor("");
                  setReceiptId(undefined);
                  if (!retryable(sendMutation.error)) sendMutation.reset();
                }}
              >
                <Space orientation="vertical" size={4} style={{ width: "100%" }}>
                  <Space wrap><Typography.Text strong>{assistant.name}</Typography.Text>{assistant.away ? <Tag color="gold">可能延迟回复</Tag> : null}</Space>
                  {assistant.intro ? <Typography.Text type="secondary">{assistant.intro}</Typography.Text> : null}
                  <Space size={[4, 4]} wrap>{assistant.topics.map((topic) => <Tag key={topic}>{topic}</Tag>)}</Space>
                </Space>
              </Button>
            </List.Item>
          )}
        />
      )}
      {selectedAssistant ? (
        <Space orientation="vertical" size={10} style={{ width: "100%" }}>
          <Typography.Text type="secondary">问询内容可能被审计，关闭后保留 {profileQuery.data?.retentionDays ?? 0} 天。</Typography.Text>
          <Input.TextArea aria-label="问题内容" value={question} autoSize={{ minRows: 4, maxRows: 8 }} maxLength={2000} placeholder="写下要问询的问题" onChange={(event) => editQuestion(event.target.value)} />
          <Space wrap>
            <Button onClick={previewQuestion} loading={previewMutation.isPending} disabled={!question.trim() || sendMutation.isPending}>预览发送内容</Button>
            <Button type="primary" onClick={confirmSend} disabled={!preview || preview.blocked || previewFor !== question.trim() || sendMutation.isPending || sendMutation.isError}>确认发送</Button>
          </Space>
          {previewMutation.isError ? <Alert type="error" showIcon title="预览失败" description={errorText(previewMutation.error)} /> : null}
          {preview ? <Alert type={preview.blocked ? "error" : "info"} showIcon title={preview.blocked ? "内容包含敏感信息，暂不能发送" : "即将发送的问题"} description={preview.blocked ? "请修改问题并重新预览。" : "请核对以下纯文本，确认后才会发送。"} /> : null}
          {preview && !preview.blocked ? <Typography.Paragraph style={{ margin: 0, whiteSpace: "pre-wrap" }}>{preview.question}</Typography.Paragraph> : null}
          {sendMutation.isError && sendMutation.variables ? (
            <Alert type="error" showIcon title="问询提交失败" description={errorText(sendMutation.error)} action={<Button onClick={() => sendMutation.mutate(sendMutation.variables!)}>重试原问询</Button>} />
          ) : null}
          {receipt ? <InquiryResult inquiry={receipt} /> : null}
        </Space>
      ) : null}
    </Space>
  );

  const inboxPane = (
    <Space orientation="vertical" size={12} style={{ width: "100%" }}>
      {inboxQuery.isError ? <Alert type={denied(inboxQuery.error) ? "warning" : "error"} showIcon title={denied(inboxQuery.error) ? "没有读取待办的权限" : "待办读取失败"} description={denied(inboxQuery.error) ? undefined : errorText(inboxQuery.error)} /> : null}
      {inboxQuery.isPending ? <Spin /> : null}
      {!inboxQuery.isPending && !inboxQuery.isError && inbox.length === 0 ? <Empty description="暂无待办问询" /> : null}
      {inbox.map((inquiry) => (
        <div key={inquiry.id} role="group" aria-label={`待办问询 ${inquiry.id}`}>
          <Space orientation="vertical" size={8} style={{ width: "100%" }}>
            <Space wrap><Tag color="gold">{INQUIRY_STATUS[inquiry.status]}</Tag><Typography.Text strong>{inquiry.callerName}</Typography.Text><Typography.Text type="secondary">{observedAt(inquiry.createdAt)}</Typography.Text></Space>
            <Typography.Paragraph style={{ margin: 0, whiteSpace: "pre-wrap" }}>{inquiry.question}</Typography.Paragraph>
            {replyFor === inquiry.id ? (
              <Space orientation="vertical" size={8} style={{ width: "100%" }}>
                <Input.TextArea aria-label="仅回复该同事的内容" value={replyText} autoSize={{ minRows: 3, maxRows: 8 }} maxLength={4000} placeholder="写下只回复给这位同事的内容" onChange={(event) => setReplyText(event.target.value)} />
                {!share ? (
                  <Space wrap>
                    <Button type="primary" loading={replyMutation.isPending} disabled={!replyText.trim()} onClick={() => replyMutation.mutate({ id: inquiry.id, answer: replyText.trim() })}>仅回复该同事</Button>
                    <Button onClick={() => { setReplyFor(""); setReplyText(""); }}>取消</Button>
                  </Space>
                ) : null}
                <Checkbox checked={share} onChange={(event) => setShare(event.target.checked)}>另外发布为共享</Checkbox>
                {share ? (
                  <Space orientation="vertical" size={8} style={{ width: "100%" }}>
                    <Select value={shareKind} onChange={(value) => { setShareKind(value); setShareLifetime(value === "work_pulse" ? 24 : 90); }} options={[{ value: "experience_card", label: "经验卡" }, { value: "work_pulse", label: "工作进度" }]} />
                    <Input aria-label="共享标题" value={shareTitle} maxLength={120} placeholder="对外公开标题" onChange={(event) => setShareTitle(event.target.value)} />
                    <Input.TextArea aria-label="对外公开摘要" value={shareSummary} autoSize={{ minRows: 2, maxRows: 5 }} maxLength={1000} placeholder="可与回复原文不同的公开摘要" onChange={(event) => setShareSummary(event.target.value)} />
                    {shareKind === "work_pulse" ? <Select aria-label="工作状态" value={shareStatus} onChange={setShareStatus} options={WORK_STATUS} /> : null}
                    <Select aria-label="共享受众" value={shareVisibility} onChange={(value) => setShareVisibility(value)} options={[{ value: "teams", label: "团队", disabled: teams.length === 0 }, { value: "projects", label: "项目", disabled: projects.length === 0 }, { value: "organization", label: "全组织" }]} />
                    {shareVisibility === "teams" ? <Select mode="multiple" aria-label="选择团队" value={shareTeams} onChange={setShareTeams} options={teams.map((value) => ({ value, label: value }))} /> : null}
                    {shareVisibility === "projects" ? <Select mode="multiple" aria-label="选择项目" value={shareProjects} onChange={setShareProjects} options={projects.map((value) => ({ value, label: value }))} /> : null}
                    {shareVisibility === "organization" ? <Alert type="info" showIcon title="全组织发布需审批；通过前不会对他人可见。" /> : null}
                    <InputNumber aria-label={shareKind === "work_pulse" ? "有效期小时" : "有效期天"} min={1} max={shareKind === "work_pulse" ? 336 : 3650} value={shareLifetime} onChange={(value) => setShareLifetime(value ?? (shareKind === "work_pulse" ? 24 : 90))} addonAfter={shareKind === "work_pulse" ? "小时" : "天"} />
                    <Button type="primary" loading={shareMutation.isPending} disabled={!replyText.trim() || !shareTitle.trim() || !shareSummary.trim() || !audienceValid(shareVisibility, shareTeams, shareProjects) || !lifetimeValid(shareKind, shareLifetime)} onClick={() => confirmShare(inquiry)}>回复并发布共享</Button>
                  </Space>
                ) : null}
                {replyMutation.isError ? <Alert type="error" showIcon title="私聊回复失败" description={errorText(replyMutation.error)} /> : null}
                {shareMutation.isError ? <Alert type="error" showIcon title="回复并发布失败；不会重试写入" description={errorText(shareMutation.error)} /> : null}
              </Space>
            ) : <Button onClick={() => openReply(inquiry)}>回复该同事</Button>}
          </Space>
        </div>
      ))}
    </Space>
  );

  const sentPane = (
    <Space orientation="vertical" size={12} style={{ width: "100%" }}>
      {sentQuery.isError ? <Alert type={denied(sentQuery.error) ? "warning" : "error"} showIcon title={denied(sentQuery.error) ? "没有读取已发出问询的权限" : "已发出问询读取失败"} description={denied(sentQuery.error) ? undefined : errorText(sentQuery.error)} /> : null}
      {sentQuery.isPending ? <Spin /> : null}
      {!sentQuery.isPending && !sentQuery.isError && sent.length === 0 ? <Empty description="还没有发出问询" /> : null}
      {sent.map((inquiry) => (
        <div key={inquiry.id}>
          <Space orientation="vertical" size={6} style={{ width: "100%" }}>
            <Space wrap><Tag color={inquiry.status === "pending" ? "gold" : "blue"}>{INQUIRY_STATUS[inquiry.status]}</Tag><Typography.Text strong>{inquiry.ownerName}</Typography.Text><Typography.Text type="secondary">{observedAt(inquiry.createdAt)}</Typography.Text></Space>
            <Typography.Paragraph style={{ margin: 0, whiteSpace: "pre-wrap" }}>{inquiry.question}</Typography.Paragraph>
            <InquiryResult inquiry={inquiry} />
          </Space>
        </div>
      ))}
    </Space>
  );

  const profilePane = (
    <Space orientation="vertical" size={14} style={{ width: "100%" }}>
      <Alert type="info" showIcon title="关闭公开不会影响你发起问询或配置名片。" description="关闭后同事看不到问询入口；已有问询仍可在收件箱处理。" />
      <Space style={{ width: "100%", justifyContent: "space-between" }}><Typography.Text strong>开放同事问询</Typography.Text><Checkbox aria-label="开放同事问询" checked={profileOpen} onChange={(event) => setProfileOpen(event.target.checked)} /></Space>
      <Space style={{ width: "100%", justifyContent: "space-between" }}><Typography.Text strong>暂离，可能延迟回复</Typography.Text><Checkbox aria-label="暂离" checked={profileAway} onChange={(event) => setProfileAway(event.target.checked)} /></Space>
      <Input.TextArea aria-label="助手简介" value={profileIntro} autoSize={{ minRows: 3, maxRows: 6 }} maxLength={280} placeholder="介绍你可以被同事问询的范围" onChange={(event) => setProfileIntro(event.target.value)} />
      <Typography.Text type="secondary">问询关闭后保留 {profileQuery.data?.retentionDays ?? 0} 天。</Typography.Text>
      <Space wrap><Button type="primary" loading={profileMutation.isPending} onClick={() => profileMutation.mutate()}>保存名片设置</Button>{profileMutation.isSuccess ? <Typography.Text type="success">已保存</Typography.Text> : null}</Space>
      {profileMutation.isError ? <Alert type="error" showIcon title="名片保存失败" description={errorText(profileMutation.error)} /> : null}
    </Space>
  );

  const assetPane = (
    <Space orientation="vertical" size={12} style={{ width: "100%" }}>
      {hasSource ? <Alert type="info" showIcon title="从当前选中来源提炼" description={source?.runId ? `已完成 Run ${source.runId}` : `消息 ${source?.messageIds?.join("、") ?? ""}`} /> : <Typography.Text type="secondary">可直接新建，或从 Heya 消息与已完成 Run 打开本页提炼。</Typography.Text>}
      <Space wrap>
        <Select aria-label="资产类型" value={assetKind} onChange={(value) => { setAssetKind(value); setAssetLifetime(value === "work_pulse" ? 24 : 90); }} options={[{ value: "skill", label: KIND_LABEL.skill }, { value: "experience_card", label: KIND_LABEL.experience_card }, { value: "work_pulse", label: KIND_LABEL.work_pulse }]} />
        {hasSource ? <Button loading={extractMutation.isPending} disabled={!assetTitle.trim() || assetKind === "work_pulse"} onClick={() => extractMutation.mutate()}>从选中来源提炼</Button> : null}
        <Button loading={createMutation.isPending} disabled={!assetTitle.trim() || !assetBody.trim()} onClick={() => createMutation.mutate(assetInput())}>新建草稿</Button>
        {asset ? <Button loading={refreshMutation.isPending} onClick={() => refreshMutation.mutate()}>刷新资产</Button> : null}
      </Space>
      <Input aria-label="资产标题" value={assetTitle} maxLength={120} placeholder="标题" onChange={(event) => setAssetTitle(event.target.value)} />
      <Input.TextArea aria-label="资产正文" value={assetBody} autoSize={{ minRows: 4, maxRows: 12 }} maxLength={12000} placeholder={assetKind === "experience_card" ? "问题 / 处理结论 / 适用条件" : "可执行步骤或工作摘要"} onChange={(event) => setAssetBody(event.target.value)} />
      <Input aria-label="适用条件" value={applicability} maxLength={1000} placeholder="适用条件（可选）" onChange={(event) => setApplicability(event.target.value)} />
      {assetKind === "work_pulse" ? (
        <Space wrap>
          <Select aria-label="工作进度状态" value={workStatus} onChange={setWorkStatus} options={WORK_STATUS} />
          <Input aria-label="阻塞原因" value={blockerReason} maxLength={1000} placeholder="阻塞原因（可选）" onChange={(event) => setBlockerReason(event.target.value)} />
        </Space>
      ) : null}
      {asset ? (
        <Space orientation="vertical" size={8} style={{ width: "100%" }}>
          <Space wrap><Tag>{KIND_LABEL[asset.kind === "mcp" ? "skill" : asset.kind]}</Tag>{asset.published ? <Tag color="green">v{asset.published.version}</Tag> : null}{asset.review?.status === "pending" ? <Tag color="gold">审批中</Tag> : null}{asset.review?.status === "rejected" ? <Tag color="red">已驳回</Tag> : null}</Space>
          <Space wrap><Button loading={saveMutation.isPending} disabled={!asset.draftDigest || !assetTitle.trim() || !assetBody.trim()} onClick={() => saveMutation.mutate()}>保存草稿摘要</Button><Button loading={trialMutation.isPending} disabled={busyAsset || !asset.draftDigest || !sessionId || !prompt.trim()} onClick={() => trialMutation.mutate()}>试跑并返回 Run</Button></Space>
          <Input aria-label="试跑提示词" value={prompt} maxLength={4000} placeholder="试跑提示词；结果仍需人工核对" onChange={(event) => setPrompt(event.target.value)} />
          <Select aria-label="发布受众" value={assetVisibility} onChange={(value) => setAssetVisibility(value)} options={[{ value: "private", label: "仅自己" }, { value: "teams", label: "团队", disabled: teams.length === 0 }, { value: "projects", label: "项目", disabled: projects.length === 0 }, { value: "organization", label: "全组织" }]} />
          {assetVisibility === "teams" ? <Select mode="multiple" aria-label="发布团队" value={assetTeams} onChange={setAssetTeams} options={teams.map((value) => ({ value, label: value }))} /> : null}
          {assetVisibility === "projects" ? <Select mode="multiple" aria-label="发布项目" value={assetProjects} onChange={setAssetProjects} options={projects.map((value) => ({ value, label: value }))} /> : null}
          {assetVisibility === "organization" ? <Alert type="info" showIcon title="全组织发布需审批；通过前不会对他人可见。" /> : null}
          {asset.kind === "work_pulse" || asset.kind === "experience_card" ? <InputNumber aria-label={asset.kind === "work_pulse" ? "Work Pulse 有效期小时" : "经验卡有效期天"} min={1} max={asset.kind === "work_pulse" ? 336 : 3650} value={assetLifetime} onChange={(value) => setAssetLifetime(value ?? (asset.kind === "work_pulse" ? 24 : 90))} addonAfter={asset.kind === "work_pulse" ? "小时" : "天"} /> : null}
          <Button type="primary" loading={publishMutation.isPending} disabled={busyAsset || !asset.draftDigest || !assetLifetimeValid || !audienceValid(assetVisibility, assetTeams, assetProjects)} onClick={() => publishMutation.mutate()}>提交发布</Button>
          {assetNotice ? <Alert type={assetNotice.includes("审批中") || assetNotice.includes("未确认") ? "warning" : "info"} showIcon title={assetNotice} /> : null}
        </Space>
      ) : null}
      {createMutation.isError ? <Alert type="error" showIcon title="新建失败" description={errorText(createMutation.error)} /> : null}
      {extractMutation.isError ? <Alert type="error" showIcon title="提炼失败" description={errorText(extractMutation.error)} /> : null}
      {saveMutation.isError ? <Alert type="error" showIcon title="保存失败" description={errorText(saveMutation.error)} /> : null}
      {trialMutation.isError ? <Alert type="error" showIcon title="试跑失败" description={errorText(trialMutation.error)} /> : null}
      {publishMutation.isError ? <Alert type="error" showIcon title="发布结果未确认；不会自动重试" description={errorText(publishMutation.error)} /> : null}
      {refreshMutation.isError ? <Alert type="error" showIcon title="资产刷新失败" description={errorText(refreshMutation.error)} /> : null}
      {asset ? <Button size="small" type="link" onClick={() => loadAsset(asset)}>将服务端资产载入编辑框</Button> : null}
    </Space>
  );

  return (
    <Drawer title="助手互联与待办" size="min(760px, 100vw)" open={open} onClose={onClose} destroyOnHidden>
      {profileQuery.isPending ? <Spin /> : profileQuery.isError ? (
        <Alert type={denied(profileQuery.error) ? "warning" : "error"} showIcon title={denied(profileQuery.error) ? "没有访问助手互联的权限" : "助手互联暂不可用"} description={denied(profileQuery.error) ? "缓存内容已隐藏；权限恢复后重新打开。" : errorText(profileQuery.error)} action={<Button onClick={() => void profileQuery.refetch()}>重试读取</Button>} />
      ) : (
        <Tabs
          activeKey={tab}
          onChange={(key) => setTab(key as MeshTab)}
          items={[
            { key: "find", label: "查找", children: findPane },
            { key: "profile", label: "我的名片", children: profilePane },
            { key: "sent", label: "已发出", children: sentPane },
            { key: "inbox", label: "收件箱", children: inboxPane },
            { key: "assets", label: "协作资产", children: assetPane },
            { key: "delegations", label: "本机委托", children: tab === "delegations" ? <AssistantMeshDelegations key={owner} owner={owner} userId={userId} /> : null },
          ]}
        />
      )}
    </Drawer>
  );
}

function InquiryResult({ inquiry }: { inquiry: MeshInquiry }) {
  if (showStatus(inquiry)) return <Typography.Text type="secondary">{INQUIRY_STATUS[inquiry.status]}</Typography.Text>;
  return (
    <Space orientation="vertical" size={4} style={{ width: "100%" }}>
      <Typography.Text strong>{inquiry.status === "answered" ? "自动答复" : "同事回复"}</Typography.Text>
      <Typography.Paragraph style={{ margin: 0, whiteSpace: "pre-wrap" }}>{inquiry.answer}</Typography.Paragraph>
      {inquiry.citations?.length ? <Typography.Text type="secondary">引用来源：{inquiry.citations.map((item) => `${item.title} v${item.version} ${observedAt(item.observedAt)}`).join("；")}</Typography.Text> : null}
    </Space>
  );
}
