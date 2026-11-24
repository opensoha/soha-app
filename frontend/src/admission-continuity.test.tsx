import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { AdmissionContinuity } from "@/admission-continuity";
import { getNetworkAdmissionChoices } from "@/api";
import { getAdmissionStatus, getNetworkLinkStatus, runAdmissionAction } from "@/native/host";
import { networkChoiceScope, writeNetworkChoicePreferences } from "@/network-choice-preferences";
import { useAppStore } from "@/store";
import type { AdmissionStatus, HostState, Session } from "@/types";

vi.mock("@/api", () => ({ getNetworkAdmissionChoices: vi.fn() }));
vi.mock("@/native/host", () => ({
  getNetworkLinkStatus: vi.fn(), getAdmissionStatus: vi.fn(), runAdmissionAction: vi.fn(),
}));

const server = "https://office.example";
const deviceId = "device-1";
const userId = "user-1";
const profileId = "strict-office";
let root: Root;
let client: QueryClient;
let container: HTMLDivElement;
const guest = { known: true, connected: true, medium: "wifi" as const, openWifiSsid: "Guest", dnsServers: [] };
const disconnected = { known: true, connected: false, dnsServers: [] };
const installed = {
  supported: true,
  profiles: [{ id: profileId, siteId: "site", ssid: "Office", accessMedium: "wifi", state: "installed", adapterId: "wifi-1" }],
  adapters: [{ id: "wifi-1", name: "Wi-Fi", medium: "wifi", enabled: true, linkUp: true }],
} as AdmissionStatus;
const choices = () => ({
  items: [{
    accessNetworkId: profileId, siteId: "site", siteName: "Office", accessMedium: "wifi" as const, ssid: "Office",
    authentication: "radius_802_1x" as const, // gitleaks:allow -- public protocol enum
    accessProfile: "full" as const, policyVersion: 1, autoConnect: true,
    strictOnline: { leaseUntil: new Date(Date.now() + 20_000).toISOString() },
  }],
  bootstrapNetworks: [{ accessNetworkId: "guest", siteId: "site", name: "Guest", ssid: "Guest", priority: 1, autoConnect: false }],
});

beforeEach(() => {
  vi.resetAllMocks();
  client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  container = document.createElement("div");
  document.body.appendChild(container);
  root = createRoot(container);
  const host = { serverUrl: server, app: { deviceId, platform: "darwin" } } as HostState;
  const session = { user: { userId } } as Session;
  useAppStore.setState({ host, session });
  writeNetworkChoicePreferences(networkChoiceScope(server, deviceId, userId), { preferred: profileId, autoConnect: [profileId] });
  vi.mocked(getNetworkAdmissionChoices).mockImplementation(async () => choices());
  vi.mocked(getNetworkLinkStatus).mockResolvedValue(disconnected);
  vi.mocked(getAdmissionStatus).mockResolvedValue(installed);
  vi.mocked(runAdmissionAction).mockResolvedValue(installed);
});

afterEach(async () => {
  await act(async () => root.unmount());
  client.clear();
  container.remove();
  localStorage.clear();
});

async function startContinuity() {
  await act(async () => {
    root.render(<QueryClientProvider client={client}><AdmissionContinuity /></QueryClientProvider>);
  });
}

it("waits for the Core lease and recovers when the App regains focus", async () => {
  vi.mocked(getNetworkAdmissionChoices).mockResolvedValueOnce({
    ...choices(), items: [{ ...choices().items[0], strictOnline: {} }],
  });
  await startContinuity();
  await vi.waitFor(() => expect(getNetworkAdmissionChoices).toHaveBeenCalledTimes(1));
  expect(runAdmissionAction).not.toHaveBeenCalled();
  await act(async () => { window.dispatchEvent(new Event("focus")); });
  await vi.waitFor(() => expect(runAdmissionAction).toHaveBeenCalledWith("connect", { profileId }));
});

it("keeps a link to an open Wi-Fi with the configured guest SSID", async () => {
  vi.mocked(getNetworkLinkStatus).mockResolvedValue(guest);
  await startContinuity();
  await vi.waitFor(() => expect(getNetworkLinkStatus).toHaveBeenCalledTimes(1));
  expect(getNetworkAdmissionChoices).not.toHaveBeenCalled();
  expect(runAdmissionAction).not.toHaveBeenCalled();
});

it("keeps a link that comes up after authorization", async () => {
  vi.mocked(getNetworkLinkStatus)
    .mockResolvedValueOnce(disconnected)
    .mockResolvedValueOnce(guest);
  await startContinuity();
  await vi.waitFor(() => expect(getNetworkLinkStatus).toHaveBeenCalledTimes(2));
  expect(runAdmissionAction).not.toHaveBeenCalled();
});
