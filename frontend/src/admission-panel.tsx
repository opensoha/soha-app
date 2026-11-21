import { ApiOutlined, WifiOutlined } from "@ant-design/icons";
import { Alert, App, Button, Checkbox, Empty, Input, Select, Space, Tag } from "antd";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useLayoutEffect, useRef, useState } from "react";
import { useText } from "@/i18n";
import {
  pruneNetworkChoicePreferences,
  readNetworkChoicePreferences,
  writeNetworkChoicePreferences,
} from "@/network-choice-preferences";
import { useAppStore } from "@/store";
import { getAdmissionStatus, getNetworkLinkStatus, runAdmissionAction } from "@/native/host";
import type {
  AdmissionAction,
  AdmissionInput,
  AdmissionStatus,
  NetworkBootstrapOption,
  NetworkConnectionOption,
  NetworkConnectionOptions,
  NetworkLinkStatus,
} from "@/types";
import "./portal-network.css";

type Medium = NetworkConnectionOption["accessMedium"];
type Selection = { profileId: string; adapterId?: string };
type Profile = AdmissionStatus["profiles"][number];

const autoConnectionAttempts = new Set<string>();

function methodSupportedFor(profile?: Profile) {
  if (profile?.eapMethod === "ttls") {
    return profile.innerMethod === "pap" && profile.supported === true &&
      (profile.credentialInteraction === "app-input" || profile.credentialInteraction === "system-prompt");
  }
  return Boolean(profile && (profile.eapMethod === undefined || profile.eapMethod === "tls") && profile.supported !== false);
}

function automaticAdmissionReady(profile: Profile, adapters: AdmissionStatus["adapters"]) {
  return profile.state === "installed" && (profile.eapMethod === undefined || profile.eapMethod === "tls") &&
    profile.credentialInteraction === undefined && profile.supported !== false &&
    adapters.some((adapter) => adapter.enabled && profile.adapterId === adapter.id &&
      (profile.accessMedium !== "wired" || adapter.linkUp));
}

function choiceKey(option: NetworkConnectionOption) {
  return option.accessNetworkId || [option.siteId, option.accessMedium, option.ssid || ""].join("|");
}

function matchesProfile(option: NetworkConnectionOption, profile: Profile) {
  if (option.accessNetworkId) return option.accessNetworkId === profile.id;
  return option.siteId === profile.siteId && option.accessMedium === profile.accessMedium &&
    (profile.accessMedium === "wired" || option.ssid === profile.ssid);
}

export function AdmissionPanel({ medium, linkState, link, options, bootstrapNetworks, optionsStatus, linkKnownDisconnected, hasHealthyLink, scope, wiredConnectSupported, enabled }: {
  medium: Medium;
  linkState: string;
  link: NetworkLinkStatus | null;
  options: NetworkConnectionOption[];
  bootstrapNetworks: NetworkBootstrapOption[];
  optionsStatus: "loading" | "error" | "ready";
  linkKnownDisconnected: boolean;
  hasHealthyLink: boolean;
  scope: string;
  wiredConnectSupported: boolean;
  enabled: boolean;
}) {
  const text = useText();
  const chinese = useAppStore((state) => state.locale) === "zh_CN";
  const demoConnectNote = chinese ? "模拟连接已发起，等待 NAS 观测。" : "Simulated connection requested. Waiting for NAS observation.";
  const { message, modal } = App.useApp();
  const queryClient = useQueryClient();
  const passwordRef = useRef("");
  const [password, setPassword] = useState("");
  const clearPassword = () => { passwordRef.current = ""; setPassword(""); };
  const [selections, setSelections] = useState<Partial<Record<Medium, Selection>>>({});
  const [preferences, setPreferences] = useState(() => readNetworkChoicePreferences(scope));
  const selection = selections[medium];
  const profileId = selection?.profileId;
  const query = useQuery({ queryKey: ["network-admission", scope], queryFn: getAdmissionStatus, enabled, retry: false, refetchInterval: 10_000 });
  const profiles = query.data?.profiles.filter((profile) => profile.accessMedium === medium) ?? [];
  const mediumOptions = options.filter((option) => option.accessMedium === medium);
  const orderedOptions = [...mediumOptions].sort((left, right) => {
    const leftPreferred = choiceKey(left) === preferences.preferred;
    const rightPreferred = choiceKey(right) === preferences.preferred;
    if (leftPreferred !== rightPreferred) return leftPreferred ? -1 : 1;
    return (left.recommendationPriority ?? Number.MAX_SAFE_INTEGER) -
      (right.recommendationPriority ?? Number.MAX_SAFE_INTEGER);
  });
  const seenProfiles = new Set<string>();
  const choices = orderedOptions.flatMap((option) => {
    const profile = profiles.find((candidate) => matchesProfile(option, candidate));
    if (!profile || seenProfiles.has(profile.id)) return [];
    seenProfiles.add(profile.id);
    return [{ key: choiceKey(option), option, profile }];
  });
  const approvedProfiles = choices.map((choice) => choice.profile);
  const selected = approvedProfiles.find((profile) => profile.id === profileId);
  const selectedChoice = choices.find((choice) => choice.profile.id === selected?.id);
  const needsPassword = selected?.eapMethod === "ttls";
  const needsAppPassword = needsPassword && selected?.credentialInteraction === "app-input";
  const systemPasswordPrompt = needsPassword && selected?.credentialInteraction === "system-prompt";
  const nasSession = needsPassword ? undefined : selectedChoice?.option.nasSession;
  const nasSessionStatus = needsPassword ? text.networkNasTtlsCannotConfirm : nasSession ? {
    pending: text.networkNasPending,
    observed: text.networkNasObserved,
    ended: text.networkNasEnded,
    unknown: text.networkNasUnknown,
  }[nasSession.state] : text.networkNasUnavailable;
  const nasReceivedAt = nasSession?.lastReceivedAt;
  const nasReceivedLabel = nasReceivedAt ? new Date(nasReceivedAt).toLocaleString(chinese ? "zh-CN" : "en-US") : undefined;
  const methodSupported = methodSupportedFor(selected);
  const passwordBytes = new TextEncoder().encode(password).length;
  const validPassword = passwordBytes > 0 && passwordBytes <= 72;
  const optionsReady = optionsStatus === "ready";
  const adapters = query.data?.adapters.filter((adapter) => adapter.medium === medium && adapter.enabled) ?? [];
  const actionScope = useRef<{ available: Set<string>; automatic: Set<string> } | null>(null);
  useLayoutEffect(() => {
    if (scope && enabled) {
      const current = optionsReady && query.isSuccess ? choices : [];
      actionScope.current = {
        available: new Set(current.map(({ profile }) => profile.id)),
        automatic: new Set(current.filter(({ key, option, profile }) =>
          option.autoConnect === true && preferences.autoConnect.includes(key) && automaticAdmissionReady(profile, adapters),
        ).map(({ profile }) => profile.id)),
      };
    }
    return () => { actionScope.current = null; };
  }, [adapters, choices, enabled, optionsReady, preferences.autoConnect, query.isSuccess, scope]);
  useLayoutEffect(() => () => { passwordRef.current = ""; }, []);

  const rememberPreferred = (key: string) => {
    setPreferences((current) => {
      const next = { ...current, preferred: key };
      writeNetworkChoicePreferences(scope, next);
      return next;
    });
  };
  const toggleAutoConnect = (key: string, checked: boolean) => {
    setPreferences((current) => {
      const values = new Set(current.autoConnect);
      if (checked) values.add(key); else values.delete(key);
      const next = { ...current, autoConnect: [...values] };
      writeNetworkChoicePreferences(scope, next);
      return next;
    });
  };

  useEffect(() => {
    passwordRef.current = "";
    setPassword("");
  }, [medium, profileId, selected?.credentialInteraction, selected?.eapMethod, selected?.state, enabled]);
  useEffect(() => {
    if (!enabled || !query.isSuccess || !query.data.supported || !optionsReady) return;
    setSelections((current) => {
      let next = current;
      for (const key of ["wifi", "wired"] as const) {
        const choice = current[key];
        const keyOptions = options.filter((option) => option.accessMedium === key);
        const candidates = keyOptions.flatMap((option) => {
          const profile = query.data.profiles.find((candidate) => matchesProfile(option, candidate));
          return profile ? [profile] : [];
        });
        const preferred = candidates.find((profile) => {
          const option = keyOptions.find((candidate) => matchesProfile(candidate, profile));
          return option && choiceKey(option) === preferences.preferred;
        });
        if (choice?.profileId && !candidates.some((profile) => profile.id === choice.profileId)) {
          next = { ...next, [key]: { profileId: "" } };
        } else if (!choice && preferred) {
          next = { ...next, [key]: { profileId: preferred.id } };
        } else if (!choice && candidates.length === 1 && candidates[0].supported !== false && candidates[0].state !== "authorization_expired") {
          next = { ...next, [key]: { profileId: candidates[0].id } };
        }
      }
      return next;
    });
  }, [enabled, optionsReady, options, preferences.preferred, query.data, query.isSuccess]);
  const validKeys = options.map(choiceKey).sort();
  const validKeySignature = JSON.stringify(validKeys);
  useEffect(() => {
    if (!enabled || !optionsReady) return;
    setPreferences((current) => {
      const next = pruneNetworkChoicePreferences(scope, JSON.parse(validKeySignature) as string[]);
      return JSON.stringify(current) === JSON.stringify(next) ? current : next;
    });
  }, [enabled, optionsReady, scope, validKeySignature]);
  const selectedAdapter = adapters.find((adapter) => adapter.id === (selected?.adapterId || selection?.adapterId));
  const profileOptions = choices.map(({ key, option, profile }) => {
    const label = [option.networkName && option.networkName !== profile.ssid ? option.networkName : undefined, profile.ssid, option.siteName]
      .filter(Boolean).join(" · ");
    return {
      value: profile.id,
      label: (
        <span>
          {label || text.networkAdmissionAuthorizedSite}
          {key === preferences.preferred ? <Tag color="blue" style={{ marginInlineStart: 8 }}>{text.networkRecentlyUsed}</Tag> : null}
        </span>
      ),
    };
  });
  const mutation = useMutation({
    mutationFn: async ({ action, input, usePassword, automatic }: { action: AdmissionAction; input?: AdmissionInput; usePassword: boolean; automatic?: boolean }) => {
      if (automatic) {
        const current = await getNetworkLinkStatus();
        if (current.connected || !current.known && !current.demo) return undefined;
      }
      const currentScope = actionScope.current;
      if (!currentScope) return undefined;
      if (input && action !== "remove") {
        const native = queryClient.getQueryState<AdmissionStatus>(["network-admission", scope]);
        const authorized = queryClient.getQueryState<NetworkConnectionOptions>(["network-connection-options", scope]);
        const profile = native?.data?.profiles.find((item) => item.id === input.profileId);
        if (!profile || native?.status !== "success" || !native.data?.supported || authorized?.status !== "success") return undefined;
        const option = authorized.data?.items.find((item) => matchesProfile(item, profile));
        if (!option || (automatic
          ? !currentScope.automatic.has(input.profileId) || option.autoConnect !== true || !automaticAdmissionReady(profile, native.data.adapters)
          : !currentScope.available.has(input.profileId))) return undefined;
      }
      // Keep the transient password out of React Query mutation variables/cache.
      const secret = passwordRef.current;
      clearPassword();
      return runAdmissionAction(action, usePassword && input ? { ...input, password: secret } : input);
    },
    onSuccess: (status, variables) => {
      if (!status || !actionScope.current) return;
      queryClient.setQueryData(["network-admission", scope], status);
      if (variables.action === "connect" || variables.action === "check") void queryClient.invalidateQueries({ queryKey: ["native-network-link"] });
      if (variables.action === "connect") {
        void queryClient.invalidateQueries({ queryKey: ["network-connection-options", scope] });
        const profile = status.profiles.find((item) => item.id === variables.input?.profileId);
        if (status.demo) void message.success(demoConnectNote);
        else if (profile?.credentialInteraction === "system-prompt") void message.info(text.networkAdmissionSystemPasswordHelp);
        else void message.success(text.networkAdmissionAssociationRequested);
      }
    },
    onError: (error, variables) => {
      if (actionScope.current) void message.error(variables.action === "connect" ? text.networkAdmissionFailed : error instanceof Error ? error.message : text.networkAdmissionFailed);
    },
    onSettled: () => { if (actionScope.current) { clearPassword(); void query.refetch(); } },
  });
  const run = (action: AdmissionAction) => {
    if ((action === "connect" || action === "prepare" || action === "open") && (!optionsReady || !selected)) return;
    const mutate = () => {
      if (!actionScope.current) return;
      mutation.mutate({
        action,
        input: action === "check" ? undefined : {
          profileId: selected?.id ?? "",
          ...(action === "prepare" ? { adapterId: selectedAdapter?.id ?? "" } : {}),
        },
        usePassword: action === "connect" && Boolean(needsAppPassword),
      });
    };
    if (action === "connect" && hasHealthyLink) {
      modal.confirm({
        title: text.networkSwitchConfirmTitle,
        content: text.networkSwitchConfirmBody,
        okText: text.networkSwitchConfirmOk,
        cancelText: text.cancel,
        onOk: mutate,
        onCancel: clearPassword,
      });
    } else {
      mutate();
    }
  };
  const autoCandidate = (() => {
    if (!enabled || !scope || mutation.isPending || !optionsReady || !linkKnownDisconnected || !query.isSuccess || !query.data.supported ||
        autoConnectionAttempts.has(scope) || (medium === "wired" && !wiredConnectSupported)) return undefined;
    return choices.find(({ key, option, profile }) => {
      if (option.autoConnect !== true || !preferences.autoConnect.includes(key)) return false;
      return automaticAdmissionReady(profile, adapters);
    });
  })();
  useEffect(() => {
    if (hasHealthyLink) autoConnectionAttempts.delete(scope);
    if (!autoCandidate || autoConnectionAttempts.has(scope)) return;
    autoConnectionAttempts.add(scope);
    mutation.mutate({ action: "connect", input: { profileId: autoCandidate.profile.id }, usePassword: false, automatic: true });
  }, [autoCandidate, hasHealthyLink, mutation, scope]);
  const applySelection = (value: string) => {
    setSelections((current) => ({ ...current, [medium]: { profileId: value } }));
    clearPassword();
    const choice = choices.find((candidate) => candidate.profile.id === value);
    if (choice) rememberPreferred(choice.key);
  };
  const canConnect = Boolean(selected?.adapterId && methodSupported && selectedAdapter &&
    (medium === "wifi" || needsPassword || wiredConnectSupported) &&
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
        disabled={unsupported || !optionsReady || query.isError || mutation.isPending || (!query.isPending && approvedProfiles.length === 0)}
        id="admission-profile"
        loading={(query.isPending || optionsStatus === "loading") && !unsupported}
        onChange={applySelection}
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
        {profileField}
        {selectedChoice ? <Checkbox
          checked={preferences.autoConnect.includes(selectedChoice.key)}
          disabled={!optionsReady || selectedChoice.option.autoConnect !== true || mutation.isPending}
          onChange={(event) => toggleAutoConnect(selectedChoice.key, event.target.checked)}
        >{text.networkAutoConnectChoice}</Checkbox> : null}
        {selectedChoice && selectedChoice.option.autoConnect !== true ? <span className="admission-trust-note">{text.networkAutoConnectPolicyOff}</span> : null}
        {medium === "wifi" || needsPassword || wiredConnectSupported ? <Button
          type="primary"
          shape="round"
          disabled={unsupported || !optionsReady || query.isError || !canConnect || mutation.isPending}
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
      {selectedChoice?.option.accessNetworkId && optionsReady ? <dl aria-label={text.networkNasSessionTitle} className="network-status-values">
        <div><dt>{text.networkNasSessionTitle}</dt><dd aria-live="polite">{nasSessionStatus}</dd></div>
        {nasReceivedAt ? <div><dt>{text.networkNasLastReceived}</dt><dd><time dateTime={nasReceivedAt}>{nasReceivedLabel}</time></dd></div> : null}
      </dl> : null}
      {unsupported ? <Alert showIcon type="info" description={text.networkAdmissionUnsupported} /> : query.isError ? (
        <Alert showIcon type="warning" title={text.networkAdmissionFailed} action={<Button size="small" onClick={() => void query.refetch()}>{text.retry}</Button>} />
      ) : <>
        {medium === "wifi" && bootstrapNetworks.length > 0 ? <Alert
          showIcon
          type="info"
          title={text.networkBootstrapTitle}
          description={<>
            <p>{text.networkBootstrapHelp}</p>
            <ul>{bootstrapNetworks.map((network) => <li key={network.accessNetworkId}>
              {network.name} · {network.ssid}{network.autoConnect ? ` · ${text.networkBootstrapAutoHint}` : ""}
            </li>)}</ul>
          </>}
        /> : null}
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
                <Button disabled={!optionsReady || !selected || !methodSupported || !selectedAdapter || selected.state === "authorization_expired" || mutation.isPending} loading={pendingAction === "prepare"} onClick={() => run("prepare")}>{text.networkAdmissionPrepare}</Button>
                {selected?.state === "installation_required" && selected.artifactPath ? <Button disabled={!optionsReady || mutation.isPending} loading={pendingAction === "open"} onClick={() => run("open")}>{text.networkAdmissionOpen}</Button> : null}
                <Button disabled={mutation.isPending} loading={pendingAction === "check"} onClick={() => run("check")}>{text.networkAdmissionCheck}</Button>
                {selected?.adapterId ? <Button danger type="text" disabled={mutation.isPending} loading={pendingAction === "remove"} onClick={() => run("remove")}>{text.networkAdmissionRemove}</Button> : null}
              </Space>
            </div>
          </div>
        </details>
        {selection && !selected ? <Alert showIcon type="warning" description={text.networkAdmissionSelectionChanged} /> : null}
        {optionsStatus === "ready" && mediumOptions.length === 0 ? <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={medium === "wifi" ? text.networkNoAuthorizedWifi : text.networkNoAuthorizedWired} /> : null}
        {optionsStatus === "ready" && mediumOptions.length > 0 && !query.isPending && choices.length === 0 ? <Alert showIcon type="info" description={<>
          {text.networkAuthorizedWithoutProfile}
          <ul>{orderedOptions.map((option) => <li key={choiceKey(option)}>{option.networkName || option.ssid || option.siteName}</li>)}</ul>
        </>} /> : null}
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
