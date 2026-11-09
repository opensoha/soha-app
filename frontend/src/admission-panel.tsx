import { Alert, App, Button, Empty, Input, Select, Space, Tag } from "antd";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useRef, useState } from "react";
import { useText } from "@/i18n";
import { getAdmissionStatus, runAdmissionAction } from "@/native/host";
import type { AdmissionAction, AdmissionInput, NetworkConnectionOption } from "@/types";

export function AdmissionPanel({ medium, options, enabled }: { medium: "wifi" | "wired"; options: NetworkConnectionOption[]; enabled: boolean }) {
  const text = useText();
  const { message } = App.useApp();
  const queryClient = useQueryClient();
  const passwordRef = useRef("");
  const [password, setPassword] = useState("");
  const clearPassword = () => { passwordRef.current = ""; setPassword(""); };
  useEffect(() => () => { passwordRef.current = ""; }, []);
  const [profileId, setProfileId] = useState("");
  const [adapterId, setAdapterId] = useState("");
  const [selectionInvalidated, setSelectionInvalidated] = useState(false);
  const query = useQuery({ queryKey: ["network-admission"], queryFn: getAdmissionStatus, enabled, retry: false, refetchInterval: 10_000 });
  const profiles = query.data?.profiles.filter((profile) => profile.accessMedium === medium) ?? [];
  const selected = profiles.find((profile) => profile.id === profileId);
  const needsPassword = selected?.eapMethod === "ttls";
  const needsAppPassword = needsPassword && selected?.credentialInteraction === "app-input";
  const systemPasswordPrompt = needsPassword && selected?.credentialInteraction === "system-prompt";
  const methodSupported = Boolean(selected && (needsPassword
    ? selected.innerMethod === "pap" && selected.supported === true && (needsAppPassword || systemPasswordPrompt)
    : (selected.eapMethod === undefined || selected.eapMethod === "tls") && selected.supported !== false));
  const passwordBytes = new TextEncoder().encode(password).length;
  const validPassword = passwordBytes > 0 && passwordBytes <= 72;
  useEffect(() => {
    passwordRef.current = "";
    setPassword("");
  }, [profileId, selected?.eapMethod, selected?.state, enabled]);
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
    mutationFn: ({ action, input }: { action: AdmissionAction; input?: AdmissionInput }) => {
      // Keep the transient password out of React Query mutation variables/cache.
      const secret = passwordRef.current;
      clearPassword();
      return runAdmissionAction(action, action === "connect" && needsAppPassword ? { ...input!, password: secret } : input);
    },
    onSuccess: (status, variables) => {
      queryClient.setQueryData(["network-admission"], status);
      if (variables.action === "connect") {
        const profile = status.profiles.find((item) => item.id === variables.input?.profileId);
        if (profile?.credentialInteraction === "system-prompt") void message.info(text.networkAdmissionSystemPasswordHelp);
        else void message.success(text.networkAdmissionAssociationRequested);
      }
    },
    onError: (error, variables) => void message.error(variables.action === "connect" ? text.networkAdmissionFailed : error instanceof Error ? error.message : text.networkAdmissionFailed),
    onSettled: () => { clearPassword(); void query.refetch(); },
  });
  const run = (action: AdmissionAction) => mutation.mutate({ action, input: action === "check" ? undefined : { profileId: selected?.id ?? "", ...(action === "prepare" ? { adapterId: selectedAdapter?.id ?? "" } : {}) } });
  const stateText = {
    available: text.networkAdmissionAvailable,
    action_required: text.networkAdmissionActionRequired,
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
      <Select aria-label={text.networkAdmissionProfile} style={{ width: "100%" }} loading={query.isPending} disabled={mutation.isPending} value={selected?.id} placeholder={text.networkAdmissionProfile} onChange={(value) => { setProfileId(value); setAdapterId(""); setSelectionInvalidated(false); clearPassword(); }} options={profiles.map((profile) => ({ value: profile.id, label: [profile.ssid, options.find((option) => option.siteId === profile.siteId)?.siteName ?? text.networkAdmissionAuthorizedSite].filter(Boolean).join(" · ") }))} />
      {selectionInvalidated ? <Alert showIcon type="warning" description={text.networkAdmissionSelectionChanged} /> : null}
      {!query.isPending && profiles.length === 0 ? <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={medium === "wifi" ? text.networkNoAuthorizedWifi : text.networkNoAuthorizedWired} /> : null}
      <Select aria-label={text.networkAdmissionAdapter} style={{ width: "100%" }} disabled={!selected || Boolean(selected.adapterId) || mutation.isPending} value={selectedAdapter?.id} placeholder={text.networkAdmissionAdapter} onChange={setAdapterId} options={adapters.map((adapter) => ({ value: adapter.id, label: `${adapter.name} · ${adapter.macAddress}` }))} />
      {selected ? <Tag color={selected.state === "installed" ? "green" : selected.state === "drift" || selected.state === "authorization_expired" ? "warning" : "default"}>{stateText[selected.state]}</Tag> : null}
      {selected ? <Tag>{needsPassword ? text.networkAdmissionPasswordMethod : text.networkAdmissionCertificateMethod}</Tag> : null}
      {selected && !methodSupported ? <Alert showIcon type="info" description={text.networkAdmissionMethodUnsupported} /> : null}
      {needsAppPassword && methodSupported && selected?.state === "installed" ? <Space orientation="vertical" style={{ width: "100%" }}>
        <Input.Password aria-label={text.networkAdmissionPassword} autoComplete="off" value={password} disabled={mutation.isPending} onChange={(event) => { passwordRef.current = event.target.value; setPassword(event.target.value); }} />
        <Alert showIcon type={password && !validPassword ? "warning" : "info"} description={password && !validPassword ? text.networkAdmissionPasswordInvalid : text.networkAdmissionPasswordHelp} />
      </Space> : null}
      {systemPasswordPrompt && methodSupported ? <Alert showIcon type="info" description={text.networkAdmissionSystemPasswordHelp} /> : null}
      <Space wrap>
        <Button type="primary" disabled={!selected || !methodSupported || !selectedAdapter || selected.state === "authorization_expired" || mutation.isPending} loading={mutation.isPending && mutation.variables.action === "prepare"} onClick={() => run("prepare")}>{text.networkAdmissionPrepare}</Button>
        {selected?.state === "installation_required" && selected.artifactPath ? <Button disabled={mutation.isPending} onClick={() => run("open")}>{text.networkAdmissionOpen}</Button> : null}
        <Button disabled={mutation.isPending} onClick={() => run("check")}>{text.networkAdmissionCheck}</Button>
        {medium === "wifi" || needsPassword ? <Button disabled={!selected || !methodSupported || (selected.state !== "installed" && selected.state !== "action_required") || needsAppPassword && !validPassword || mutation.isPending} onClick={() => run("connect")}>{medium === "wifi" ? text.networkAdmissionConnect : text.networkAdmissionConnectNetwork}</Button> : null}
        {selected?.adapterId ? <Button danger disabled={mutation.isPending} onClick={() => run("remove")}>{text.networkAdmissionRemove}</Button> : null}
      </Space>
      {selected?.state === "installation_required" ? <Alert showIcon type="info" description={text.networkAdmissionInstallHelp} /> : null}
      <Alert showIcon type="warning" description={text.networkAdmissionTrustHelp} />
      {medium === "wired" ? <Alert showIcon type="info" description={text.networkAdmissionWiredHelp} /> : null}
      {query.data?.diagnostic ? <Alert showIcon type="warning" title={text.networkAdmissionAttention} description={text.networkAdmissionRetryHelp} /> : null}
    </Space>
  );
}
