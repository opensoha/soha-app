import { Alert, App, Button, Empty, Select, Space, Tag } from "antd";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { useText } from "@/i18n";
import { getAdmissionStatus, runAdmissionAction } from "@/native/host";
import type { AdmissionAction, AdmissionInput, NetworkConnectionOption } from "@/types";

export function AdmissionPanel({ medium, options, enabled }: { medium: "wifi" | "wired"; options: NetworkConnectionOption[]; enabled: boolean }) {
  const text = useText();
  const { message } = App.useApp();
  const queryClient = useQueryClient();
  const [profileId, setProfileId] = useState("");
  const [adapterId, setAdapterId] = useState("");
  const [selectionInvalidated, setSelectionInvalidated] = useState(false);
  const query = useQuery({ queryKey: ["network-admission"], queryFn: getAdmissionStatus, enabled, retry: false, refetchInterval: 10_000 });
  const profiles = query.data?.profiles.filter((profile) => profile.accessMedium === medium) ?? [];
  const selected = profiles.find((profile) => profile.id === profileId);
  useEffect(() => {
    if (query.isSuccess && profileId && !selected) {
      setProfileId("");
      setAdapterId("");
      setSelectionInvalidated(true);
    }
  }, [profileId, selected, query.isSuccess]);
  const adapters = query.data?.adapters.filter((adapter) => adapter.medium === medium && adapter.enabled) ?? [];
  const selectedAdapter = adapters.find((adapter) => adapter.id === (selected?.adapterId || adapterId));
  const mutation = useMutation({
    mutationFn: ({ action, input }: { action: AdmissionAction; input?: AdmissionInput }) => runAdmissionAction(action, input),
    onSuccess: (status, variables) => {
      queryClient.setQueryData(["network-admission"], status);
      if (variables.action === "connect") void message.success(text.networkAdmissionAssociationRequested);
    },
    onError: (error) => void message.error(error instanceof Error ? error.message : text.networkAdmissionFailed),
    onSettled: () => { void query.refetch(); },
  });
  const run = (action: AdmissionAction) => mutation.mutate({ action, input: action === "check" ? undefined : { profileId: selected?.id ?? "", ...(action === "prepare" ? { adapterId: selectedAdapter?.id ?? "" } : {}) } });
  const stateText = {
    available: text.networkAdmissionAvailable,
    installation_required: text.networkAdmissionInstallRequired,
    activation_pending: text.networkAdmissionActivationPending,
    installed: text.networkAdmissionInstalled,
    drift: text.networkAdmissionDrift,
    authorization_expired: text.networkAdmissionExpired,
  };

  if (!enabled || query.data?.supported === false) return <Alert showIcon type="info" description={text.networkAdmissionUnsupported} />;
  if (query.isError) return <Alert showIcon type="warning" title={text.networkAdmissionFailed} action={<Button size="small" onClick={() => void query.refetch()}>{text.retry}</Button>} />;

  return (
    <Space orientation="vertical" size="middle" style={{ width: "100%" }}>
      <Select aria-label={text.networkAdmissionProfile} style={{ width: "100%" }} loading={query.isPending} value={selected?.id} placeholder={text.networkAdmissionProfile} onChange={(value) => { setProfileId(value); setAdapterId(""); setSelectionInvalidated(false); }} options={profiles.map((profile) => ({ value: profile.id, label: [profile.ssid, options.find((option) => option.siteId === profile.siteId)?.siteName ?? text.networkAdmissionAuthorizedSite].filter(Boolean).join(" · ") }))} />
      {selectionInvalidated ? <Alert showIcon type="warning" description={text.networkAdmissionSelectionChanged} /> : null}
      {!query.isPending && profiles.length === 0 ? <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={medium === "wifi" ? text.networkNoAuthorizedWifi : text.networkNoAuthorizedWired} /> : null}
      <Select aria-label={text.networkAdmissionAdapter} style={{ width: "100%" }} disabled={!selected || Boolean(selected.adapterId)} value={selectedAdapter?.id} placeholder={text.networkAdmissionAdapter} onChange={setAdapterId} options={adapters.map((adapter) => ({ value: adapter.id, label: `${adapter.name} · ${adapter.macAddress}` }))} />
      {selected ? <Tag color={selected.state === "installed" ? "green" : selected.state === "drift" || selected.state === "authorization_expired" ? "warning" : "default"}>{stateText[selected.state]}</Tag> : null}
      <Space wrap>
        <Button type="primary" disabled={!selected || !selectedAdapter || selected.state === "authorization_expired" || mutation.isPending} loading={mutation.isPending && mutation.variables.action === "prepare"} onClick={() => run("prepare")}>{text.networkAdmissionPrepare}</Button>
        {selected?.state === "installation_required" && selected.artifactPath ? <Button disabled={mutation.isPending} onClick={() => run("open")}>{text.networkAdmissionOpen}</Button> : null}
        <Button disabled={mutation.isPending} onClick={() => run("check")}>{text.networkAdmissionCheck}</Button>
        {medium === "wifi" ? <Button disabled={!selected || selected.state !== "installed" || mutation.isPending} onClick={() => run("connect")}>{text.networkAdmissionConnect}</Button> : null}
        {selected?.adapterId ? <Button danger disabled={mutation.isPending} onClick={() => run("remove")}>{text.networkAdmissionRemove}</Button> : null}
      </Space>
      {selected?.state === "installation_required" ? <Alert showIcon type="info" description={text.networkAdmissionInstallHelp} /> : null}
      <Alert showIcon type="warning" description={text.networkAdmissionTrustHelp} />
      {medium === "wired" ? <Alert showIcon type="info" description={text.networkAdmissionWiredHelp} /> : null}
      {query.data?.diagnostic ? <Alert showIcon type="warning" title={text.networkAdmissionAttention} description={text.networkAdmissionRetryHelp} /> : null}
    </Space>
  );
}
