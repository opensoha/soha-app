import { useEffect, useMemo, useRef, useState } from "react";
import { CopyOutlined, LinkOutlined, SearchOutlined } from "@ant-design/icons";
import {
  Alert,
  App,
  Button,
  Checkbox,
  Empty,
  Input,
  Modal,
  Segmented,
  Select,
  Space,
  Spin,
  Switch,
  Tag,
  Typography,
} from "antd";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  deployWorkspaceHostedApp,
  listMyHostedApps,
  searchAppHostingAudience,
  validateExternalHostedAppURL,
} from "@/api";
import { useText } from "@/i18n";
import { openBrowserURL } from "@/native/host";
import { useAppStore } from "@/store";
import type {
  AppHostingAudienceTeam,
  AppHostingAudienceUser,
  HostedApp,
  HostedAppVisibilityInput,
  HostedAppVisibilityMode,
  WorkspaceHostedAppDeploymentRequest,
  WorkspaceHostedAppDeploymentResult,
  WorkspaceHostedAppSource,
} from "@/types";

export interface WorkspaceAppPublishDraft {
  defaultName?: string;
  defaultDescription?: string;
  source: WorkspaceHostedAppSource;
}

export function normalizeWorkspacePublishPath(rawPath: string): string | null {
  const trimmed = rawPath.trim();
  if (!trimmed || trimmed === ".") return ".";
  if (trimmed.length > 512 || /[\0\r\n]/.test(trimmed)) return null;
  const cleaned = trimmed.replace(/^\/+/, "").replace(/\/+$/, "");
  if (!cleaned) return ".";
  const segments = cleaned.split("/");
  if (segments.some((segment) => !segment || segment === ".." || segment === ".")) {
    return null;
  }
  return segments.join("/");
}

export function WorkspaceAppPublishModal({
  draft,
  open,
  onClose,
  onPublished,
}: {
  draft: WorkspaceAppPublishDraft | null;
  open: boolean;
  onClose: () => void;
  onPublished?: (result: WorkspaceHostedAppDeploymentResult) => void;
}) {
  const { message } = App.useApp();
  const text = useText();
  const queryClient = useQueryClient();
  const serverURL = useAppStore((state) => state.host?.serverUrl);
  const currentUserId = useAppStore(
    (state) =>
      state.bootstrap?.currentUser?.userId || state.session?.user?.userId || "",
  );

  const [mode, setMode] = useState<"create" | "update">("create");
  const [selectedAppId, setSelectedAppId] = useState("");
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [spaFallback, setSpaFallback] = useState(false);
  const [visibilityMode, setVisibilityMode] =
    useState<HostedAppVisibilityMode>("private");
  const [selectedTeamIds, setSelectedTeamIds] = useState<string[]>([]);
  const [selectedUserIds, setSelectedUserIds] = useState<string[]>([]);
  const [knownTeams, setKnownTeams] = useState<Record<string, AppHostingAudienceTeam>>({});
  const [knownUsers, setKnownUsers] = useState<Record<string, AppHostingAudienceUser>>({});
  const [audienceQuery, setAudienceQuery] = useState("");
  const [debouncedAudienceQuery, setDebouncedAudienceQuery] = useState("");
  const [visibilityReason, setVisibilityReason] = useState("");
  const [visibilityChanged, setVisibilityChanged] = useState(false);
  const [localError, setLocalError] = useState("");
  const [receipt, setReceipt] =
    useState<WorkspaceHostedAppDeploymentResult | null>(null);
  const idempotencyRef = useRef<{ signature: string; key: string } | null>(
    null,
  );

  useEffect(() => {
    if (!open || !draft) return;
    setMode("create");
    setSelectedAppId("");
    setName(draft.defaultName?.trim() || "");
    setDescription(draft.defaultDescription?.trim() || "");
    setSpaFallback(false);
    setVisibilityMode("private");
    setSelectedTeamIds([]);
    setSelectedUserIds([]);
    setAudienceQuery("");
    setDebouncedAudienceQuery("");
    setVisibilityReason("");
    setVisibilityChanged(false);
    setLocalError("");
    setReceipt(null);
    idempotencyRef.current = null;
  }, [draft, open]);

  useEffect(() => {
    const trimmed = audienceQuery.trim();
    if (!trimmed) {
      setDebouncedAudienceQuery("");
      return;
    }
    const timer = window.setTimeout(() => setDebouncedAudienceQuery(trimmed), 120);
    return () => window.clearTimeout(timer);
  }, [audienceQuery]);

  const myAppsQuery = useQuery({
    queryKey: ["app-hosting", "my-apps"],
    queryFn: listMyHostedApps,
    enabled: open && Boolean(draft),
    retry: false,
  });

  const audienceCandidatesQuery = useQuery({
    queryKey: ["app-hosting", "audience-candidates", debouncedAudienceQuery],
    queryFn: () => searchAppHostingAudience(debouncedAudienceQuery || undefined, 20),
    enabled: open && Boolean(draft) && visibilityMode === "selected",
    retry: false,
  });

  useEffect(() => {
    const candidates = audienceCandidatesQuery.data;
    if (!candidates) return;
    setKnownTeams((prev) => {
      const next = { ...prev };
      for (const team of candidates.teams) next[team.id] = team;
      return next;
    });
    setKnownUsers((prev) => {
      const next = { ...prev };
      for (const user of candidates.users) next[user.id] = user;
      return next;
    });
  }, [audienceCandidatesQuery.data]);

  const deployableApps = useMemo<HostedApp[]>(
    () =>
      (myAppsQuery.data || []).filter(
        (item) =>
          item.status !== "offline" && item.status !== "suspended_by_admin",
      ),
    [myAppsQuery.data],
  );

  const selectedExistingApp = useMemo<HostedApp | undefined>(
    () => deployableApps.find((item) => item.id === selectedAppId),
    [deployableApps, selectedAppId],
  );
  const isSelectedAppOwner =
    !selectedExistingApp ||
    !currentUserId ||
    selectedExistingApp.ownerUserId === currentUserId;
  const canEditMetadataAndVisibility =
    mode === "create" || isSelectedAppOwner;

  const selectExistingApp = (appId: string) => {
    setSelectedAppId(appId);
    setVisibilityChanged(false);
    setLocalError("");
    const existing = deployableApps.find((item) => item.id === appId);
    if (!existing) return;
    setName(existing.name);
    setDescription(existing.description || "");
    setSpaFallback(existing.spaFallback);
    setVisibilityMode(existing.visibility.mode);
    setSelectedTeamIds(existing.visibility.teamIds || []);
    setSelectedUserIds(existing.visibility.userIds || []);
    setVisibilityReason("");
  };

  const narrowedExistingVisibility = useMemo(() => {
    if (
      mode !== "update" ||
      !selectedExistingApp ||
      !isSelectedAppOwner ||
      !visibilityChanged
    ) {
      return false;
    }
    const previous = selectedExistingApp.visibility;
    if (previous.mode === "organization" && visibilityMode !== "organization") {
      return true;
    }
    if (previous.mode === "selected") {
      if (visibilityMode === "private") return true;
      if (visibilityMode === "selected") {
        const nextTeams = new Set(selectedTeamIds);
        const nextUsers = new Set(selectedUserIds);
        return (
          (previous.teamIds || []).some((id) => !nextTeams.has(id)) ||
          (previous.userIds || []).some((id) => !nextUsers.has(id))
        );
      }
    }
    return false;
  }, [
    isSelectedAppOwner,
    mode,
    selectedExistingApp,
    selectedTeamIds,
    selectedUserIds,
    visibilityChanged,
    visibilityMode,
  ]);

  const deployMutation = useMutation({
    mutationFn: (requestInput: WorkspaceHostedAppDeploymentRequest) =>
      deployWorkspaceHostedApp(requestInput),
    retry: false,
    onSuccess: (result) => {
      setReceipt(result);
      setLocalError("");
      void queryClient.invalidateQueries({ queryKey: ["app-hosting", "my-apps"] });
      void queryClient.invalidateQueries({ queryKey: ["portal", "colleague-apps"] });
      onPublished?.(result);
    },
    onError: (error) => {
      setLocalError(error instanceof Error ? error.message : "发布失败");
    },
  });

  const handleSubmit = () => {
    if (!draft || deployMutation.isPending) return;
    const trimmedName = name.trim();
    if (mode === "update" && !selectedAppId) {
      setLocalError(text.publishSelectAppRequired);
      return;
    }
    if (canEditMetadataAndVisibility && !trimmedName) {
      setLocalError(text.publishAppNameRequired);
      return;
    }
    const includeVisibility =
      mode === "create" || (isSelectedAppOwner && visibilityChanged);
    if (
      includeVisibility &&
      visibilityMode === "selected" &&
      selectedTeamIds.length === 0 &&
      selectedUserIds.length === 0
    ) {
      setLocalError(text.publishAudienceRequired);
      return;
    }
    setLocalError("");

    const visibility: HostedAppVisibilityInput =
      visibilityMode === "selected"
        ? {
            mode: "selected",
            teamIds: selectedTeamIds,
            userIds: selectedUserIds,
          }
        : { mode: visibilityMode };

    const trimmedDescription = description.trim();
    const trimmedReason = visibilityReason.trim();
    const payloadWithoutKey: Omit<
      WorkspaceHostedAppDeploymentRequest,
      "idempotencyKey"
    > =
      mode === "create"
        ? {
            name: trimmedName,
            ...(trimmedDescription ? { description: trimmedDescription } : {}),
            spaFallback,
            visibility,
            ...(visibilityMode === "organization" && trimmedReason
              ? { visibilityReason: trimmedReason }
              : {}),
            source: draft.source,
          }
        : {
            appId: selectedAppId,
            ...(isSelectedAppOwner && trimmedName ? { name: trimmedName } : {}),
            ...(isSelectedAppOwner
              ? { description: trimmedDescription }
              : {}),
            spaFallback,
            ...(includeVisibility ? { visibility } : {}),
            ...(includeVisibility &&
            visibilityMode === "organization" &&
            trimmedReason
              ? { visibilityReason: trimmedReason }
              : {}),
            source: draft.source,
          };
    const signature = JSON.stringify(payloadWithoutKey);
    if (idempotencyRef.current?.signature !== signature) {
      idempotencyRef.current = {
        signature,
        key: crypto.randomUUID(),
      };
    }

    deployMutation.mutate({
      ...payloadWithoutKey,
      idempotencyKey: idempotencyRef.current.key,
    });
  };

  const toggleTeam = (teamId: string, checked: boolean) => {
    setVisibilityChanged(true);
    setSelectedTeamIds((prev) =>
      checked
        ? prev.includes(teamId)
          ? prev
          : [...prev, teamId]
        : prev.filter((id) => id !== teamId),
    );
  };

  const toggleUser = (userId: string, checked: boolean) => {
    setVisibilityChanged(true);
    setSelectedUserIds((prev) =>
      checked
        ? prev.includes(userId)
          ? prev
          : [...prev, userId]
        : prev.filter((id) => id !== userId),
    );
  };

  const handleOpenPublishedURL = () => {
    if (!receipt) return;
    try {
      const safeURL = validateExternalHostedAppURL(receipt.app.url, serverURL);
      void openBrowserURL(safeURL).catch(() =>
        void message.error(text.portalLaunchFailed),
      );
    } catch {
      void message.error(text.portalLaunchFailed);
    }
  };

  const handleCopyPublishedURL = async () => {
    if (!receipt) return;
    try {
      const safeURL = validateExternalHostedAppURL(receipt.app.url, serverURL);
      await navigator.clipboard.writeText(safeURL);
      void message.success(text.publishLinkCopied);
    } catch {
      void message.error(text.publishCopyFailed);
    }
  };

  const pendingApproval =
    receipt?.app.pendingVisibilityApproval?.status === "pending";

  return (
    <Modal
      cancelButtonProps={{ disabled: deployMutation.isPending }}
      cancelText={text.cancel}
      confirmLoading={deployMutation.isPending}
      destroyOnHidden
      footer={
        receipt ? (
          <Space wrap>
            <Button icon={<CopyOutlined />} onClick={() => void handleCopyPublishedURL()}>
              {text.publishCopyLink}
            </Button>
            <Button
              icon={<LinkOutlined />}
              onClick={handleOpenPublishedURL}
              type="primary"
            >
              {text.publishOpenInBrowser}
            </Button>
            <Button onClick={onClose}>{text.publishDone}</Button>
          </Space>
        ) : undefined
      }
      okText={text.publishSubmit}
      onCancel={() => {
        if (!deployMutation.isPending) onClose();
      }}
      onOk={handleSubmit}
      open={open}
      title={text.publishModalTitle}
    >
      {receipt ? (
        <Space orientation="vertical" size={12} style={{ width: "100%" }}>
          <Alert
            showIcon
            title={
              receipt.created ? text.publishSuccessCreated : text.publishSuccessUpdated
            }
            type="success"
          />
          {pendingApproval ? (
            <Alert
              showIcon
              title={text.publishPendingApprovalBanner}
              type="warning"
            />
          ) : null}
          <div>
            <Typography.Text strong>{receipt.app.name}</Typography.Text>
            <Tag style={{ marginInlineStart: 8 }}>
              v{receipt.revision.revisionNumber}
            </Tag>
            <Typography.Paragraph code style={{ marginBlock: "8px 0" }}>
              {receipt.app.url}
            </Typography.Paragraph>
          </div>
        </Space>
      ) : (
        <Space orientation="vertical" size={12} style={{ width: "100%" }}>
          {localError ? <Alert showIcon title={localError} type="error" /> : null}

          <Segmented
            aria-label={text.publishModalTitle}
            block
            disabled={deployMutation.isPending}
            onChange={(value) => {
              const nextMode = value === "update" ? "update" : "create";
              setMode(nextMode);
              setVisibilityChanged(false);
              setLocalError("");
              if (nextMode === "create") {
                setSelectedAppId("");
                setName(draft?.defaultName?.trim() || "");
                setDescription(draft?.defaultDescription?.trim() || "");
                setSpaFallback(false);
                setVisibilityMode("private");
                setSelectedTeamIds([]);
                setSelectedUserIds([]);
              }
            }}
            options={[
              { label: text.publishModeCreate, value: "create" },
              { label: text.publishModeUpdate, value: "update" },
            ]}
            value={mode}
          />

          {mode === "update" ? (
            <div>
              <Typography.Text>{text.publishSelectApp}</Typography.Text>
              <Select
                aria-label={text.publishSelectApp}
                disabled={deployMutation.isPending}
                loading={myAppsQuery.isFetching}
                notFoundContent={text.publishNoExistingApps}
                onChange={selectExistingApp}
                options={deployableApps.map((item) => ({
                  label: `${item.name} (${item.host})`,
                  value: item.id,
                }))}
                placeholder={text.publishSelectAppPlaceholder}
                style={{ width: "100%", marginTop: 4 }}
                value={selectedAppId || undefined}
              />
              {selectedExistingApp && !isSelectedAppOwner ? (
                <Alert
                  showIcon
                  style={{ marginTop: 8 }}
                  title="协作者发版模式：仅更新版本与路由配置，作品名称和可见范围保持作者设置不变。"
                  type="info"
                />
              ) : null}
            </div>
          ) : null}

          {canEditMetadataAndVisibility ? (
            <>
              <div>
                <Typography.Text>{text.publishAppName}</Typography.Text>
                <Input
                  aria-label={text.publishAppName}
                  disabled={deployMutation.isPending}
                  maxLength={128}
                  onChange={(event) => setName(event.target.value)}
                  placeholder={text.publishAppNamePlaceholder}
                  style={{ marginTop: 4 }}
                  value={name}
                />
              </div>

              <div>
                <Typography.Text>{text.publishAppDescription}</Typography.Text>
                <Input.TextArea
                  aria-label={text.publishAppDescription}
                  disabled={deployMutation.isPending}
                  maxLength={1024}
                  onChange={(event) => setDescription(event.target.value)}
                  placeholder={text.publishAppDescriptionPlaceholder}
                  rows={2}
                  style={{ marginTop: 4 }}
                  value={description}
                />
              </div>
            </>
          ) : null}

          <div
            style={{
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              gap: 12,
            }}
          >
            <div>
              <Typography.Text>{text.publishSpaFallback}</Typography.Text>
              <div>
                <Typography.Text style={{ fontSize: 12 }} type="secondary">
                  {text.publishSpaFallbackHelp}
                </Typography.Text>
              </div>
            </div>
            <Switch
              aria-label={text.publishSpaFallback}
              checked={spaFallback}
              disabled={deployMutation.isPending}
              onChange={setSpaFallback}
            />
          </div>

          {canEditMetadataAndVisibility ? (
            <div>
              <Typography.Text>{text.publishVisibility}</Typography.Text>
              <div style={{ marginTop: 4 }}>
                <Segmented
                  aria-label={text.publishVisibility}
                  block
                  disabled={deployMutation.isPending}
                  onChange={(value) => {
                    setVisibilityMode(value as HostedAppVisibilityMode);
                    setVisibilityChanged(true);
                    setLocalError("");
                  }}
                  options={[
                    { label: text.publishVisibilityPrivate, value: "private" },
                    { label: text.publishVisibilitySelected, value: "selected" },
                    {
                      label: text.publishVisibilityOrganization,
                      value: "organization",
                    },
                  ]}
                  value={visibilityMode}
                />
              </div>
            </div>
          ) : null}

          {narrowedExistingVisibility ? (
            <Alert showIcon title={text.publishNarrowWarning} type="info" />
          ) : null}

          {canEditMetadataAndVisibility && visibilityMode === "selected" ? (
            <Space orientation="vertical" size={8} style={{ width: "100%" }}>
              <Input
                allowClear
                aria-label={text.publishAudienceSearch}
                disabled={deployMutation.isPending}
                onChange={(event) => setAudienceQuery(event.target.value)}
                placeholder={text.publishAudienceSearchPlaceholder}
                prefix={<SearchOutlined />}
                value={audienceQuery}
              />
              {selectedTeamIds.length > 0 || selectedUserIds.length > 0 ? (
                <Space size={[4, 4]} wrap>
                  {selectedTeamIds.map((teamId) => (
                    <Tag
                      closable={!deployMutation.isPending}
                      key={`team:${teamId}`}
                      onClose={() => toggleTeam(teamId, false)}
                    >
                      {knownTeams[teamId]?.name || teamId}
                    </Tag>
                  ))}
                  {selectedUserIds.map((userId) => (
                    <Tag
                      closable={!deployMutation.isPending}
                      key={`user:${userId}`}
                      onClose={() => toggleUser(userId, false)}
                    >
                      {knownUsers[userId]?.displayName || userId}
                    </Tag>
                  ))}
                </Space>
              ) : null}
              <div
                style={{
                  maxHeight: 200,
                  overflowY: "auto",
                  padding: "8px 10px",
                  border: "1px solid var(--border)",
                  borderRadius: 8,
                }}
              >
                {audienceCandidatesQuery.isPending ? (
                  <Spin size="small" />
                ) : audienceCandidatesQuery.isError ? (
                  <Button
                    onClick={() => void audienceCandidatesQuery.refetch()}
                    size="small"
                  >
                    {text.retry}
                  </Button>
                ) : !audienceCandidatesQuery.data?.teams.length &&
                  !audienceCandidatesQuery.data?.users.length ? (
                  <Empty
                    description={text.publishAudienceEmpty}
                    image={Empty.PRESENTED_IMAGE_SIMPLE}
                  />
                ) : (
                  <Space orientation="vertical" size={8} style={{ width: "100%" }}>
                    {audienceCandidatesQuery.data.teams.length > 0 ? (
                      <div>
                        <Typography.Text style={{ fontSize: 12 }} type="secondary">
                          {text.publishAudienceTeams}
                        </Typography.Text>
                        <div style={{ display: "grid", gap: 4, marginTop: 4 }}>
                          {audienceCandidatesQuery.data.teams.map((team) => (
                            <Checkbox
                              checked={selectedTeamIds.includes(team.id)}
                              disabled={deployMutation.isPending}
                              key={team.id}
                              onChange={(event) =>
                                toggleTeam(team.id, event.target.checked)
                              }
                            >
                              {team.name}
                            </Checkbox>
                          ))}
                        </div>
                      </div>
                    ) : null}
                    {audienceCandidatesQuery.data.users.length > 0 ? (
                      <div>
                        <Typography.Text style={{ fontSize: 12 }} type="secondary">
                          {text.publishAudienceUsers}
                        </Typography.Text>
                        <div style={{ display: "grid", gap: 4, marginTop: 4 }}>
                          {audienceCandidatesQuery.data.users.map((user) => (
                            <Checkbox
                              checked={selectedUserIds.includes(user.id)}
                              disabled={deployMutation.isPending}
                              key={user.id}
                              onChange={(event) =>
                                toggleUser(user.id, event.target.checked)
                              }
                            >
                              {user.displayName} ({user.username})
                              {user.department ? ` · ${user.department}` : ""}
                            </Checkbox>
                          ))}
                        </div>
                      </div>
                    ) : null}
                  </Space>
                )}
              </div>
            </Space>
          ) : null}

          {canEditMetadataAndVisibility && visibilityMode === "organization" ? (
            <div>
              <Typography.Text>{text.publishVisibilityReason}</Typography.Text>
              <Input.TextArea
                aria-label={text.publishVisibilityReason}
                disabled={deployMutation.isPending}
                maxLength={500}
                onChange={(event) => {
                  setVisibilityReason(event.target.value);
                  setVisibilityChanged(true);
                }}
                placeholder={text.publishVisibilityReasonPlaceholder}
                rows={2}
                style={{ marginTop: 4 }}
                value={visibilityReason}
              />
            </div>
          ) : null}
        </Space>
      )}
    </Modal>
  );
}
