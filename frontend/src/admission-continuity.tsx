import { useLayoutEffect } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { canSwitchToStrictWifi } from "@/admission-continuity-policy";
import { getNetworkAdmissionChoices } from "@/api";
import { getAdmissionStatus, getNetworkLinkStatus, runAdmissionAction } from "@/native/host";
import { networkChoiceScope, readNetworkChoicePreferences } from "@/network-choice-preferences";
import { useAppStore } from "@/store";

const probeInterval = 5_000;
const resumeGap = 25_000;
const maxAttempts = 2;

export function AdmissionContinuity() {
  const server = useAppStore((state) => state.host?.serverUrl ?? "");
  const device = useAppStore((state) => state.host?.app.deviceId ?? "");
  const platform = useAppStore((state) => state.host?.app.platform);
  const user = useAppStore((state) => state.session?.user.userId ?? "");
  const scope = networkChoiceScope(server, device, user);
  const client = useQueryClient();

  useLayoutEffect(() => {
    if (!scope || !["darwin", "windows", "linux"].includes(platform ?? "")) return;
    let disposed = false;
    let running = false;
    let lastProbe = Date.now();
    let wasConnected: boolean | undefined;
    let attempts = 0;
    let lastAttempt = 0;
    const isCurrent = () => {
      const state = useAppStore.getState();
      return !disposed && scope === networkChoiceScope(state.host?.serverUrl ?? "", state.host?.app.deviceId ?? "", state.session?.user.userId ?? "");
    };
    const probe = async () => {
      const now = Date.now();
      if (running || !isCurrent()) return;
      if (now - lastProbe >= resumeGap) attempts = 0;
      lastProbe = now;
      const preference = readNetworkChoicePreferences(scope);
      if (preference.autoConnect.length === 0 || client.isMutating({ mutationKey: ["network-admission-operation", scope] })) return;
      running = true;
      try {
        const link = await getNetworkLinkStatus();
        if (!isCurrent() || link.known !== true || link.demo) return;
        if (link.connected !== wasConnected) {
          wasConnected = link.connected;
          attempts = 0;
        }
        if (link.connected || attempts >= maxAttempts || now - lastAttempt < 10_000) return;
        const authorized = await client.fetchQuery({
          queryKey: ["network-connection-options", scope],
          queryFn: () => getNetworkAdmissionChoices(device),
          staleTime: 0,
        });
        if (!isCurrent()) return;
        const candidates = authorized.items.filter((option) =>
          option.accessNetworkId && option.autoConnect && preference.autoConnect.includes(option.accessNetworkId) &&
          canSwitchToStrictWifi(option, link, Date.now()),
        );
        if (candidates.length === 0) return;
        const state = await getAdmissionStatus();
        if (!isCurrent() || !state.supported || state.demo) return;
        candidates.sort((left, right) => {
          const preferred = Number(right.accessNetworkId === preference.preferred) - Number(left.accessNetworkId === preference.preferred);
          return preferred || (left.recommendationPriority ?? Infinity) - (right.recommendationPriority ?? Infinity);
        });
        const target = candidates.find((option) => state.profiles.some((profile) =>
          profile.id === option.accessNetworkId && profile.siteId === option.siteId && profile.ssid === option.ssid &&
          profile.accessMedium === "wifi" && profile.state === "installed" && profile.supported !== false &&
          (profile.eapMethod === "tls" || profile.eapMethod === undefined) && profile.credentialInteraction === undefined &&
          state.adapters.some((adapter) => adapter.id === profile.adapterId && adapter.medium === "wifi" && adapter.enabled),
        ));
        const profileId = target?.accessNetworkId;
        if (!target || !profileId) return;
        const current = await getNetworkLinkStatus();
        if (!isCurrent() || client.isMutating({ mutationKey: ["network-admission-operation", scope] }) ||
          !readNetworkChoicePreferences(scope).autoConnect.includes(profileId) ||
          !canSwitchToStrictWifi(target, current, Date.now())) return;
        attempts++;
        lastAttempt = Date.now();
        const result = await runAdmissionAction("connect", { profileId });
        if (isCurrent()) client.setQueryData(["network-admission", scope], result);
      } catch {
        // A later probe can retry once. The native network page renders connection errors and status.
      } finally {
        running = false;
      }
    };
    const wake = () => { void probe(); };
    const timer = window.setInterval(wake, probeInterval);
    window.addEventListener("focus", wake);
    window.addEventListener("online", wake);
    document.addEventListener("visibilitychange", wake);
    wake();
    return () => {
      disposed = true;
      window.clearInterval(timer);
      window.removeEventListener("focus", wake);
      window.removeEventListener("online", wake);
      document.removeEventListener("visibilitychange", wake);
    };
  }, [client, device, platform, scope]);
  return null;
}
