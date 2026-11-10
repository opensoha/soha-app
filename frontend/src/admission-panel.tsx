import { ApiOutlined, WifiOutlined } from "@ant-design/icons";
import { Alert, App, Button, Empty, Input, Select, Space, Tag } from "antd";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useRef, useState } from "react";
import { useText } from "@/i18n";
import { useAppStore } from "@/store";
import { getAdmissionStatus, runAdmissionAction } from "@/native/host";
import type { AdmissionAction, AdmissionInput, AdmissionStatus, NetworkConnectionOption, NetworkLinkStatus } from "@/types";
import "./portal-network.css";

type Medium = NetworkConnectionOption["accessMedium"];
type Selection = { profileId: string; adapterId?: string };
type Profile = AdmissionStatus["profiles"][number];

function methodSupportedFor(profile?: Profile) {
  if (profile?.eapMethod === "ttls") {
    return profile.innerMethod === "pap" && profile.supported === true &&
      (profile.credentialInteraction === "app-input" || profile.credentialInteraction === "system-prompt");
  }
  return Boolean(profile && (profile.eapMethod === undefined || profile.eapMethod === "tls") && profile.supported !== false);
}

export function AdmissionPanel({ medium, linkState, link, options, enabled }: {
  medium: Medium;
  linkState: string;
  link: NetworkLinkStatus | null;
  options: NetworkConnectionOption[];
  enabled: boolean;
}) {
  const text = useText();
  const chinese = useAppStore((state) => state.locale) === "zh_CN";
  const demoConnectNote = chinese ? "模拟连接已发起，等待 NAS 观测。" : "Simulated connection requested. Waiting for NAS observation.";
  const { message } = App.useApp();
  const queryClient = useQueryClient();
  const passwordRef = useRef("");
  const [password, setPassword] = useState("");
  const clearPassword = () => { passwordRef.current = ""; setPassword(""); };
  useEffect(() => () => { passwordRef.current = ""; }, []);
  const [selections, setSelections] = useState<Partial<Record<Medium, Selection>>>({});
  const selection = selections[medium];
  const profileId = selection?.profileId;
  const query = useQuery({ queryKey: ["network-admission"], queryFn: getAdmissionStatus, enabled, retry: false, refetchInterval: 10_000 });
  const profiles = query.data?.profiles.filter((profile) => profile.accessMedium === medium) ?? [];
  const selected = profiles.find((profile) => profile.id === profileId);
  const needsPassword = selected?.eapMethod === "ttls";
  const needsAppPassword = needsPassword && selected?.credentialInteraction === "app-input";
  const systemPasswordPrompt = needsPassword && selected?.credentialInteraction === "system-prompt";
  const methodSupported = methodSupportedFor(selected);
  const passwordBytes = new TextEncoder().encode(password).length;
  const validPassword = passwordBytes > 0 && passwordBytes <= 72;
  useEffect(() => {
    passwordRef.current = "";
    setPassword("");
  }, [medium, profileId, selected?.credentialInteraction, selected?.eapMethod, selected?.state, enabled]);
  useEffect(() => {
    if (!enabled || !query.isSuccess || !query.data.supported) return;
    setSelections((current) => {
      let next = current;
      for (const key of ["wifi", "wired"] as const) {
        const choice = current[key];
        const candidates = query.data.profiles.filter((profile) => profile.accessMedium === key);
        if (choice?.profileId && !candidates.some((profile) => profile.id === choice.profileId)) {
          next = { ...next, [key]: { profileId: "" } };
        } else if (!choice && candidates.length === 1 && candidates[0].supported !== false && candidates[0].state !== "authorization_expired") {
          next = { ...next, [key]: { profileId: candidates[0].id } };
        }
      }
      return next;
    });
  }, [enabled, query.data, query.isSuccess]);
  const adapters = query.data?.adapters.filter((adapter) => adapter.medium === medium && adapter.enabled) ?? [];
  const selectedAdapter = adapters.find((adapter) => adapter.id === (selected?.adapterId || selection?.adapterId));
  const profileOptions = profiles.map((profile) => {
    const site = options.find((option) => option.accessMedium === medium && option.siteId === profile.siteId &&
      (medium === "wired" || option.ssid === profile.ssid));
    return { value: profile.id, label: [profile.ssid, site?.siteName ?? text.networkAdmissionAuthorizedSite].filter(Boolean).join(" · ") };
  });
  const mutation = useMutation({
    mutationFn: ({ action, input, usePassword }: { action: AdmissionAction; input?: AdmissionInput; usePassword: boolean }) => {
      // Keep the transient password out of React Query mutation variables/cache.
      const secret = passwordRef.current;
      clearPassword();
      return runAdmissionAction(action, usePassword && input ? { ...input, password: secret } : input);
    },
    onSuccess: (status, variables) => {
      queryClient.setQueryData(["network-admission"], status);
      if (variables.action === "connect" || variables.action === "check") void queryClient.invalidateQueries({ queryKey: ["native-network-link"] });
      if (variables.action === "connect") {
        const profile = status.profiles.find((item) => item.id === variables.input?.profileId);
        if (status.demo) void message.success(demoConnectNote);
        else if (profile?.credentialInteraction === "system-prompt") void message.info(text.networkAdmissionSystemPasswordHelp);
        else void message.success(text.networkAdmissionAssociationRequested);
      }
    },
    onError: (error, variables) => void message.error(variables.action === "connect" ? text.networkAdmissionFailed : error instanceof Error ? error.message : text.networkAdmissionFailed),
    onSettled: () => { clearPassword(); void query.refetch(); },
  });
  const run = (action: AdmissionAction) => {
    mutation.mutate({
      action,
      input: action === "check" ? undefined : {
        profileId: selected?.id ?? "",
        ...(action === "prepare" ? { adapterId: selectedAdapter?.id ?? "" } : {}),
      },
      usePassword: action === "connect" && Boolean(needsAppPassword),
    });
  };
  const canConnect = Boolean(selected?.adapterId && methodSupported && selectedAdapter &&
    (medium === "wifi" || needsPassword) &&
    (selected.state === "installed" || selected.state === "action_required") &&
    (!needsAppPassword || validPassword));
  const unsupported = !enabled || query.data?.supported === false;
  const pendingAction = mutation.isPending ? mutation.variables.action : undefined;
  const stateText = {
    available: text.networkAdmissionAvailable,
    action_required: text.networkAdmissionActionRequired,
    installation_required: text.networkAdmissionInstallRequired,
    activation_pending: text.networkAdmissionActivationPending,
    installed: needsPassword ? text.networkAdmissionPasswordReady : text.networkAdmissionInstalled,
    drift: text.networkAdmissionDrift,
    authorization_expired: text.networkAdmissionExpired,
  };
  const profileLabel = medium === "wifi" ? text.networkChooseWifi : text.networkAdmissionProfile;
  const profileField = (
    <div className="admission-connect-field">
      {medium === "wired" ? <label htmlFor="admission-profile">{profileLabel}</label> : null}
      <Select
        aria-label={profileLabel}
        disabled={unsupported || query.isError || mutation.isPending || (!query.isPending && profiles.length === 0)}
        id="admission-profile"
        loading={query.isPending && !unsupported}
        onChange={(value) => {
          setSelections((current) => ({ ...current, [medium]: { profileId: value } }));
          clearPassword();
        }}
        options={profileOptions}
        placeholder={profileLabel}
        value={selected?.id}
      />
    </div>
  );

  return (
    <>
      <header className="network-connect-control admission-connect-header">
        <span aria-hidden="true" className="network-card-icon">{medium === "wifi" ? <WifiOutlined /> : <ApiOutlined />}</span>
        <h2>{medium === "wifi" ? text.networkWifi : text.networkWired}</h2>
        <p aria-live="polite">
          {text.networkLocalLink} · <span className={link ? "network-state-connected" : undefined}>{linkState}</span>
        </p>
        {medium === "wifi" ? profileField : null}
        {medium === "wifi" || needsPassword ? <Button
          type="primary"
          shape="round"
          disabled={unsupported || query.isError || !canConnect || mutation.isPending}
          loading={pendingAction === "connect" && mutation.variables?.input?.profileId === selected?.id}
          onClick={() => run("connect")}
        >{medium === "wifi" ? text.networkAdmissionConnect : text.networkAdmissionConnectWired}</Button> : null}
        {medium === "wired" && !link && !query.data?.demo ? <p>{text.networkWiredPlugIn}</p> : null}
      </header>
      <dl aria-label={text.networkLinkDetails} className="network-status-values">
        <div><dt>{text.networkIPAddress}</dt><dd>{link?.ipAddress || "—"}</dd></div>
        <div><dt>{text.networkGatewayAddress}</dt><dd>{link?.gateway || "—"}</dd></div>
        <div><dt>{text.networkDNSServers}</dt><dd>{link?.dnsServers.join(", ") || "—"}</dd></div>
      </dl>
      {unsupported ? <Alert showIcon type="info" description={text.networkAdmissionUnsupported} /> : query.isError ? (
        <Alert showIcon type="warning" title={text.networkAdmissionFailed} action={<Button size="small" onClick={() => void query.refetch()}>{text.retry}</Button>} />
      ) : <>
        {needsAppPassword && methodSupported && selected?.state === "installed" ? <Space orientation="vertical" style={{ width: "100%" }}>
          <Input.Password aria-label={text.networkAdmissionPassword} autoComplete="off" value={password} disabled={mutation.isPending} onChange={(event) => { passwordRef.current = event.target.value; setPassword(event.target.value); }} />
          <Alert showIcon type={password && !validPassword ? "warning" : "info"} description={password && !validPassword ? text.networkAdmissionPasswordInvalid : text.networkAdmissionPasswordHelp} />
        </Space> : null}
        <details className="admission-settings">
          <summary>{text.networkAdmissionSettings}</summary>
          <div className="admission-connect-settings">
            <div className="admission-connect-badges">
              {selected ? <>
                <Tag color={selected.state === "installed" ? "success" : selected.state === "drift" || selected.state === "authorization_expired" ? "warning" : "default"}>{stateText[selected.state]}</Tag>
                <Tag>{needsPassword ? text.networkAdmissionPasswordMethod : text.networkAdmissionCertificateMethod}</Tag>
              </> : <Tag>{text.networkRadius8021X}</Tag>}
            </div>
            <div className="admission-connect-fields">
              {medium === "wired" ? profileField : null}
              <div className="admission-connect-field">
                <label htmlFor="admission-adapter">{text.networkAdmissionAdapter}</label>
                <Select
                  aria-label={text.networkAdmissionAdapter}
                  disabled={!selected || Boolean(selected.adapterId) || mutation.isPending}
                  id="admission-adapter"
                  onChange={(value) => {
                    if (selected) setSelections((current) => ({ ...current, [medium]: { profileId: selected.id, adapterId: value } }));
                  }}
                  options={adapters.map((adapter) => ({ value: adapter.id, label: `${adapter.name} · ${adapter.macAddress}` }))}
                  placeholder={text.networkAdmissionAdapter}
                  value={selectedAdapter?.id}
                />
              </div>
            </div>
            {selected && !needsPassword && (selected.state === "installed" || selected.state === "action_required") ?
              <p className="admission-trust-note">{text.networkAdmissionTrustHelp}</p> : null}
            <div className="admission-connect-actions">
              <Space wrap>
                <Button disabled={!selected || !methodSupported || !selectedAdapter || selected.state === "authorization_expired" || mutation.isPending} loading={pendingAction === "prepare"} onClick={() => run("prepare")}>{text.networkAdmissionPrepare}</Button>
                {selected?.state === "installation_required" && selected.artifactPath ? <Button disabled={mutation.isPending} loading={pendingAction === "open"} onClick={() => run("open")}>{text.networkAdmissionOpen}</Button> : null}
                <Button disabled={mutation.isPending} loading={pendingAction === "check"} onClick={() => run("check")}>{text.networkAdmissionCheck}</Button>
                {selected?.adapterId ? <Button danger type="text" disabled={mutation.isPending} loading={pendingAction === "remove"} onClick={() => run("remove")}>{text.networkAdmissionRemove}</Button> : null}
              </Space>
            </div>
          </div>
        </details>
        {selection && !selected ? <Alert showIcon type="warning" description={text.networkAdmissionSelectionChanged} /> : null}
        {!query.isPending && profiles.length === 0 ? <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={medium === "wifi" ? text.networkNoAuthorizedWifi : text.networkNoAuthorizedWired} /> : null}
        {selected && !methodSupported ? <Alert showIcon type="info" description={text.networkAdmissionMethodUnsupported} /> : null}
        {systemPasswordPrompt && methodSupported ? <Alert showIcon type="info" description={query.data?.demo ? (chinese ? "演示环境会模拟密码认证。" : "Password authentication is simulated in this demo.") : text.networkAdmissionSystemPasswordHelp} /> : null}
        {selected?.state === "installation_required" ? <Alert showIcon type="info" description={text.networkAdmissionInstallHelp} /> : null}
        {selected && selected.state !== "installed" && selected.state !== "action_required" ? <Alert showIcon type="warning" description={text.networkAdmissionTrustHelp} /> : null}
        {medium === "wired" && selected && !needsPassword ? <Alert showIcon type="info" description={text.networkAdmissionWiredHelp} /> : null}
        {query.data?.diagnostic ? <Alert showIcon type="warning" title={text.networkAdmissionAttention} description={text.networkAdmissionRetryHelp} /> : null}
      </>}
    </>
  );
}
