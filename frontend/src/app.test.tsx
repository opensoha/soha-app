import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { App as AntApp, ConfigProvider } from "antd";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import {
  afterEach,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
  vi,
} from "vitest";
import { DesktopApp } from "@/app";
import {
  ApiError,
  changePassword,
  getAnnouncementInbox,
  getAuthProviders,
  getBootstrap,
  getLoginOptions,
  getNetworkConnectionOptions,
  getPortalBootstrap,
  getProfile,
  loginWithProvider,
  loginWithPassword,
  logoutServer,
  markAnnouncementRead,
  registerEndpointDevice,
  restoreSession,
  setSessionListener,
  updateProfile,
} from "@/api";
import {
  HostError,
  activateServerSwitch,
  checkForUpdates,
  checkServer,
  clearMihomoApp,
  clearHostSession,
  configureMihomoApp,
  connectNetwork,
  disconnectNetwork,
  getHostState,
  getMihomoAppStatus,
  getNetworkLinkStatus,
  getNetworkStatus,
  getSoftwareTask,
  getUpdateStatus,
  installSoftware,
  installUpdate,
  listSoftware,
  openBrowserURL,
  prepareServerSwitch,
  refreshMihomoApp,
  selectMihomoApp,
} from "@/native/host";
import { useAppStore } from "@/store";
import type { HostState } from "@/types";

vi.mock("@/native/host", () => ({
  HostError: class HostError extends Error {
    constructor(
      readonly status: number,
      readonly code: string,
      message: string,
      readonly requestId?: string,
    ) {
      super(message);
    }
  },
  getHostState: vi.fn().mockResolvedValue({
    serverUrl: "https://soha.example.com",
    configurationSource: "saved",
    managedByEnvironment: false,
    app: {
      name: "Soha",
      version: "test",
      platform: "darwin",
      arch: "arm64",
      deviceId: "endpoint-mac-1",
      hostname: "macbook.local",
      deviceType: "laptop",
      reportedFacts: {
        osName: "macOS",
        architecture: "arm64",
        agentVersion: "test",
        collectedAt: "2026-09-03T09:00:00Z",
        networkInterfaces: [
          {
            name: "en0",
            displayName: "Wi-Fi",
            kind: "physical",
            status: "up",
            macAddress: "00:11:22:33:44:55",
            ipv4Addresses: ["192.0.2.10"],
            ipv6Addresses: [],
            dnsServers: ["192.0.2.53"],
          },
        ],
      },
      logDirectory: "/tmp/logs",
      updateSupported: false,
    },
  }),
  checkServer: vi.fn().mockResolvedValue({
    status: "online",
    serverUrl: "https://soha.example.com",
  }),
  checkForUpdates: vi.fn(),
  getUpdateStatus: vi.fn(),
  installUpdate: vi.fn(),
  clearHostSession: vi.fn().mockResolvedValue(undefined),
  getNetworkStatus: vi.fn(),
  getNetworkLinkStatus: vi.fn(),
  connectNetwork: vi.fn(),
  disconnectNetwork: vi.fn(),
  getMihomoAppStatus: vi.fn(),
  configureMihomoApp: vi.fn(),
  selectMihomoApp: vi.fn(),
  refreshMihomoApp: vi.fn(),
  clearMihomoApp: vi.fn(),
  prepareServerSwitch: vi.fn(),
  activateServerSwitch: vi.fn(),
  openLogDirectory: vi.fn(),
  listSoftware: vi.fn(),
  installSoftware: vi.fn(),
  getSoftwareTask: vi.fn(),
  openBrowserURL: vi.fn(),
}));

vi.mock("@/api", () => {
  const user = {
    userId: "user-1",
    userName: "admin",
    email: "admin@soha.local",
    roles: [],
    teams: [],
    projects: [],
    tags: [],
  };
  return {
    ApiError: class ApiError extends Error {
      constructor(
        readonly status: number,
        readonly code: string,
        message: string,
        readonly requestId?: string,
      ) {
        super(message);
      }
    },
    setAccessToken: vi.fn(),
    setSessionListener: vi.fn(),
    restoreSession: vi
      .fn()
      .mockResolvedValue({ accessToken: "access-token", user }),
    getBootstrap: vi.fn().mockResolvedValue({
      user,
      currentUser: user,
      permissionSnapshot: { permissionKeys: [] },
      branding: {},
    }),
    getAnnouncementInbox: vi
      .fn()
      .mockResolvedValue({ items: [], unreadCount: 0 }),
    getLoginOptions: vi.fn(),
    getNetworkConnectionOptions: vi.fn(),
    getAuthProviders: vi.fn(),
    loginWithProvider: vi.fn(),
    loginWithPassword: vi.fn(),
    logoutServer: vi.fn(),
    markAnnouncementRead: vi.fn(),
    registerEndpointDevice: vi.fn(),
    getProfile: vi.fn(),
    updateProfile: vi.fn(),
    changePassword: vi.fn(),
    getPortalApplication: vi.fn(),
    getPortalBootstrap: vi.fn(),
    launchPortalApplication: vi.fn(),
    setPortalFavorite: vi.fn(),
  };
});

let container: HTMLDivElement;
let root: Root;

const principal = {
  userId: "user-1",
  userName: "admin",
  email: "admin@soha.local",
  roles: [],
  teams: [],
  projects: [],
  tags: [],
};

const hostState: HostState = {
  serverUrl: "https://soha.example.com",
  configurationSource: "saved" as const,
  managedByEnvironment: false,
  app: {
    name: "Soha",
    version: "test",
    platform: "darwin",
    arch: "arm64",
    deviceId: "endpoint-mac-1",
    hostname: "macbook.local",
    deviceType: "laptop",
    reportedFacts: {
      osName: "macOS",
      architecture: "arm64",
      agentVersion: "test",
      collectedAt: "2026-09-03T09:00:00Z",
      networkInterfaces: [
        {
          name: "en0",
          displayName: "Wi-Fi",
          kind: "physical",
          status: "up",
          macAddress: "00:11:22:33:44:55",
          ipv4Addresses: ["192.0.2.10"],
          ipv6Addresses: [],
          dnsServers: ["192.0.2.53"],
        },
      ],
    },
    logDirectory: "/tmp/logs",
    updateSupported: false,
  },
};

const softwarePackage = {
  id: "soha-agent",
  name: "Soha Agent",
  description: "组织批准的桌面代理",
  publisher: "OpenSoha",
  category: "Developer Tools",
  version: "1.2.3",
  size: 12_345_678,
};

const queuedSoftwareTask = {
  id: "task-1",
  softwareId: softwarePackage.id,
  name: softwarePackage.name,
  state: "queued" as const,
  progress: 0,
  message: "等待下载",
};

beforeAll(() => {
  vi.stubGlobal(
    "ResizeObserver",
    class {
      observe() {}
      unobserve() {}
      disconnect() {}
    },
  );
});

const disabledUpdateStatus = {
  supported: false,
  installMode: "disabled" as const,
  state: "unconfigured" as const,
  currentVersion: "0.2.0",
};

const disconnectedNetworkStatus = {
  state: "disconnected" as const,
  runtimeId: "endpoint-1",
  deviceId: "device-1",
  configurationVersion: 0,
  policyVersion: 0,
  uptimeSeconds: 10,
};

const availableUpdateStatus = {
  supported: true,
  installMode: "self" as const,
  state: "available" as const,
  currentVersion: "0.2.0",
  availableVersion: "0.2.1",
  downloadMode: "delta" as const,
  releaseURL: "https://github.com/opensoha/soha-app/releases/tag/v0.2.1",
};

const bootstrap = {
  user: principal,
  currentUser: principal,
  permissionSnapshot: { permissionKeys: [] },
  branding: {},
};

describe("desktop app", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(getHostState).mockResolvedValue(hostState);
    vi.mocked(checkServer).mockResolvedValue({
      status: "online",
      serverUrl: "https://soha.example.com",
    });
    vi.mocked(getUpdateStatus).mockResolvedValue(disabledUpdateStatus);
    vi.mocked(checkForUpdates).mockResolvedValue(disabledUpdateStatus);
    vi.mocked(installUpdate).mockResolvedValue(disabledUpdateStatus);
    vi.mocked(openBrowserURL).mockResolvedValue(undefined);
    vi.mocked(listSoftware).mockResolvedValue({ items: [] });
    vi.mocked(installSoftware).mockResolvedValue({ task: queuedSoftwareTask });
    vi.mocked(getSoftwareTask).mockResolvedValue({
      task: {
        ...queuedSoftwareTask,
        state: "completed",
        progress: 100,
        message: "安装器已打开",
      },
    });
    vi.mocked(clearHostSession).mockResolvedValue(undefined);
    vi.mocked(getNetworkStatus).mockResolvedValue(disconnectedNetworkStatus);
    vi.mocked(getNetworkLinkStatus).mockResolvedValue({
      connected: true,
      medium: "wifi",
      interfaceName: "en0",
      ipAddress: "192.0.2.10",
      gateway: "192.0.2.1",
      dnsServers: ["192.0.2.53"],
    });
    vi.mocked(connectNetwork).mockResolvedValue({
      ...disconnectedNetworkStatus,
      state: "connected",
      siteId: "site-1",
      networkSpaceId: "space-1",
      sessionId: "session-1",
    });
    vi.mocked(disconnectNetwork).mockResolvedValue(disconnectedNetworkStatus);
    vi.mocked(getMihomoAppStatus).mockResolvedValue({
      mode: "app_subscription",
      profileId: "mihomo-1",
      profileRevision: 1,
      configured: false,
      proxies: [],
    });
    vi.mocked(configureMihomoApp).mockResolvedValue({
      mode: "app_subscription",
      profileId: "mihomo-1",
      profileRevision: 1,
      configured: true,
      selectedProxy: "edge-a",
      proxies: ["edge-a"],
    });
    vi.mocked(selectMihomoApp).mockResolvedValue({
      mode: "app_subscription",
      profileId: "mihomo-1",
      profileRevision: 1,
      configured: true,
      selectedProxy: "edge-a",
      proxies: ["edge-a"],
    });
    vi.mocked(refreshMihomoApp).mockResolvedValue({
      mode: "app_subscription",
      profileId: "mihomo-1",
      profileRevision: 1,
      configured: true,
      selectedProxy: "edge-a",
      proxies: ["edge-a"],
    });
    vi.mocked(clearMihomoApp).mockResolvedValue({
      mode: "app_subscription",
      profileId: "mihomo-1",
      profileRevision: 1,
      configured: false,
      proxies: [],
    });
    vi.mocked(restoreSession).mockResolvedValue({
      accessToken: "access-token",
      user: principal,
    });
    vi.mocked(getBootstrap).mockResolvedValue(bootstrap);
    vi.mocked(getAnnouncementInbox).mockResolvedValue({
      items: [],
      unreadCount: 0,
    });
    vi.mocked(getLoginOptions).mockResolvedValue({
      localPasswordLoginEnabled: true,
      verification: { sliderEnabled: false },
    });
    vi.mocked(getAuthProviders).mockResolvedValue([]);
    vi.mocked(getNetworkConnectionOptions).mockResolvedValue([
      {
        siteId: "site-1",
        siteName: "上海总部",
        accessMedium: "wifi",
        ssid: "Soha-Staff",
        authentication: "radius_802_1x",
        accessProfile: "full",
        policyVersion: 7,
      },
      {
        siteId: "site-1",
        siteName: "上海总部",
        accessMedium: "wired",
        authentication: "radius_802_1x",
        accessProfile: "full",
        policyVersion: 7,
      },
    ]);
    vi.mocked(loginWithPassword).mockResolvedValue({
      accessToken: "password-token",
      user: principal,
    });
    vi.mocked(logoutServer).mockResolvedValue(undefined);
    vi.mocked(markAnnouncementRead).mockResolvedValue(undefined);
    vi.mocked(registerEndpointDevice).mockResolvedValue(undefined);
    vi.mocked(changePassword).mockResolvedValue(undefined);
    localStorage.clear();
    useAppStore.setState({
      host: null,
      connection: null,
      session: null,
      bootstrap: null,
      themeMode: "system",
      locale: "zh_CN",
      portalCardSize: "standard",
      networkConnection: { selectedWifiKey: "", wifiAutoConnect: false, wiredAutoConnect: false },
    });
    container = document.createElement("div");
    document.body.appendChild(container);
    root = createRoot(container);
  });

  afterEach(async () => {
    await act(async () => root.unmount());
    container.remove();
  });

  it("restores a session into the App-owned home with one desktop portal entry", async () => {
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    });
    await act(async () => {
      root.render(
        <ConfigProvider>
          <AntApp>
            <QueryClientProvider client={queryClient}>
              <DesktopApp />
            </QueryClientProvider>
          </AntApp>
        </ConfigProvider>,
      );
    });
    await act(async () => {
      await vi.waitFor(() => expect(container.textContent).toContain("首页"));
    });

    expect(container.textContent).toContain("admin");
    expect(container.textContent).toContain("个人资料");
    expect(container.textContent).toContain("设置");
    expect(container.textContent).toContain("当前账号没有查看公告的权限");
    expect(
      container.querySelector(".status-band")?.getAttribute("aria-label"),
    ).toBe("会话状态");
    expect(container.textContent).toContain("软件库");
    expect(container.textContent).toContain("应用门户");
    expect(getAnnouncementInbox).not.toHaveBeenCalled();
    expect(registerEndpointDevice).toHaveBeenCalledWith("endpoint-mac-1", {
      name: "macbook.local",
      hostname: "macbook.local",
      platform: "darwin",
      deviceType: "laptop",
      reportedFacts: expect.objectContaining({ architecture: "arm64" }),
    });
  });

  it("logs in with a password and commits bootstrap before showing home", async () => {
    vi.mocked(restoreSession).mockResolvedValueOnce(null);
    const queryClient = await renderApp();
    await act(async () => {
      await vi.waitFor(() => expect(getLoginOptions).toHaveBeenCalledOnce());
      await vi.waitFor(() => expect(getAuthProviders).toHaveBeenCalledOnce());
      await vi.waitFor(() =>
        expect(
          queryClient.getQueryState(["auth", "login-options"])?.status,
        ).toBe("success"),
      );
      await vi.waitFor(() =>
        expect(queryClient.getQueryState(["auth", "providers"])?.status).toBe(
          "success",
        ),
      );
    });
    await waitForUI(() =>
      expect(
        container.querySelector('input[autocomplete="username"]'),
      ).not.toBeNull(),
    );

    await setInput(
      container.querySelector('input[autocomplete="username"]'),
      "admin",
    );
    await setInput(
      container.querySelector('input[autocomplete="current-password"]'),
      "secret-password",
    );
    const signIn = findButton(container, "登录");
    expect(signIn).not.toBeNull();
    await act(async () => signIn?.click());
    await act(async () => {
      await vi.waitFor(() => expect(container.textContent).toContain("首页"));
    });

    expect(loginWithPassword).toHaveBeenCalledWith("admin", "secret-password");
    expect(getBootstrap).toHaveBeenCalledTimes(1);
    expect(useAppStore.getState().session?.accessToken).toBe("password-token");
    expect(useAppStore.getState().bootstrap?.currentUser.userId).toBe("user-1");
  });

  it("treats an unreachable default Server as unconfigured", async () => {
    vi.mocked(getHostState).mockResolvedValueOnce({
      ...hostState,
      serverUrl: "http://127.0.0.1:8080",
      configurationSource: "default",
    });
    vi.mocked(checkServer).mockResolvedValueOnce({
      status: "offline",
      serverUrl: "http://127.0.0.1:8080",
      code: "server_unreachable",
    });

    await renderApp();
    await waitForUI(() =>
      expect(container.textContent).toContain("尚未连接组织服务"),
    );

    expect(useAppStore.getState().connection).toMatchObject({
      status: "unconfigured",
      code: "server_not_configured",
    });
    expect(container.textContent).toContain("检查并连接");
  });

  it("keeps an online Server distinct when bootstrap fails and retries startup", async () => {
    vi.mocked(getBootstrap)
      .mockRejectedValueOnce(
        new ApiError(503, "upstream_unavailable", "Try again later"),
      )
      .mockResolvedValueOnce(bootstrap);

    await renderApp();
    await waitForUI(() =>
      expect(container.textContent).toContain("无法加载桌面会话"),
    );

    expect(useAppStore.getState().connection?.status).toBe("online");
    expect(container.textContent).not.toContain("尚未连接组织服务");

    await act(async () => findButton(container, "重试")?.click());
    await waitForUI(() => expect(container.textContent).toContain("首页"));

    expect(restoreSession).toHaveBeenCalledTimes(2);
    expect(getBootstrap).toHaveBeenCalledTimes(2);
  });

  it("redirects direct authenticated routes to login without a session", async () => {
    const queryClient = await renderApp(["/settings"]);
    await waitForLoginQueries(queryClient);
    await waitForUI(() => expect(container.textContent).toContain("登录 Soha"));

    expect(container.textContent).not.toContain("管理这个桌面客户端的外观");
  });

  it("protects direct portal routes with the existing App session guard", async () => {
    const queryClient = await renderApp(["/portal"]);
    await waitForLoginQueries(queryClient);
    await waitForUI(() => expect(container.textContent).toContain("登录 Soha"));

    expect(getPortalBootstrap).not.toHaveBeenCalled();
  });

  it("returns to login with a session-expired message when refresh invalidates the session", async () => {
    const queryClient = await renderAppToHome();
    const listener = vi
      .mocked(setSessionListener)
      .mock.calls.find(([candidate]) => typeof candidate === "function")?.[0];
    expect(listener).toBeTypeOf("function");

    await act(async () => listener?.(null));
    await waitForLoginQueries(queryClient);
    await waitForUI(() =>
      expect(document.body.textContent).toContain("会话已过期，请重新登录"),
    );

    expect(useAppStore.getState().session).toBeNull();
    expect(container.textContent).toContain("登录 Soha");
  });

  it("shows a credential error without committing a failed password login", async () => {
    vi.mocked(restoreSession).mockResolvedValueOnce(null);
    vi.mocked(loginWithPassword).mockRejectedValueOnce(
      new ApiError(401, "invalid_credentials", "Unauthorized"),
    );
    const queryClient = await renderApp();
    await waitForLoginQueries(queryClient);
    await waitForUI(() =>
      expect(
        container.querySelector('input[autocomplete="username"]'),
      ).not.toBeNull(),
    );

    await setInput(
      container.querySelector('input[autocomplete="username"]'),
      "admin",
    );
    await setInput(
      container.querySelector('input[autocomplete="current-password"]'),
      "wrong-password",
    );
    await act(async () => findButton(container, "登录")?.click());
    await act(async () => {
      await vi.waitFor(() =>
        expect(document.body.textContent).toContain(
          "登录失败，请检查账号和密码",
        ),
      );
    });

    expect(loginWithPassword).toHaveBeenCalledWith("admin", "wrong-password");
    expect(getBootstrap).not.toHaveBeenCalled();
    expect(useAppStore.getState().session).toBeNull();
  });

  it("ignores the Server slider option and submits the password form directly", async () => {
    vi.mocked(restoreSession).mockResolvedValueOnce(null);
    vi.mocked(getLoginOptions).mockResolvedValueOnce({
      localPasswordLoginEnabled: true,
      verification: { sliderEnabled: true },
    });
    vi.mocked(loginWithPassword).mockRejectedValueOnce(
      new ApiError(401, "invalid_credentials", "Unauthorized"),
    );
    const queryClient = await renderApp();
    await waitForLoginQueries(queryClient);
    await waitForUI(() =>
      expect(
        container.querySelector('input[autocomplete="username"]'),
      ).not.toBeNull(),
    );

    const signIn = findButton(container, "登录");
    expect(container.querySelector('[role="slider"]')).toBeNull();
    expect(container.textContent).not.toContain("登录验证");
    expect(signIn?.disabled).toBe(false);
    expect(
      container.querySelector('input[autocomplete="current-password"]'),
    ).not.toBeNull();

    await setInput(
      container.querySelector('input[autocomplete="username"]'),
      "admin",
    );
    await setInput(
      container.querySelector('input[autocomplete="current-password"]'),
      "wrong-password",
    );
    await act(async () => signIn?.click());
    await waitForUI(() =>
      expect(document.body.textContent).toContain("登录失败，请检查账号和密码"),
    );

    expect(loginWithPassword).toHaveBeenCalledWith("admin", "wrong-password");
    expect(getBootstrap).not.toHaveBeenCalled();
    expect(useAppStore.getState().session).toBeNull();
  });

  it("keeps theme controls in Settings and marks macOS layouts for the titlebar safe area", async () => {
    vi.mocked(restoreSession).mockResolvedValueOnce(null);
    const queryClient = await renderApp();
    await waitForLoginQueries(queryClient);
    await waitForUI(() =>
      expect(container.querySelector(".login-screen")).not.toBeNull(),
    );

    expect(
      container.querySelector(".login-screen")?.getAttribute("data-platform"),
    ).toBe("darwin");
    expect(container.querySelector('button[aria-label="深色"]')).toBeNull();
    expect(container.querySelector('button[aria-label="浅色"]')).toBeNull();
  });

  it("does not start provider login while password login is pending", async () => {
    vi.mocked(restoreSession).mockResolvedValueOnce(null);
    vi.mocked(getAuthProviders).mockResolvedValueOnce([
      { id: "oidc-main", type: "oidc", name: "Corporate OIDC", enabled: true },
    ]);
    let resolvePassword!: (session: {
      accessToken: string;
      user: typeof principal;
    }) => void;
    vi.mocked(loginWithPassword).mockImplementationOnce(
      () =>
        new Promise((resolve) => {
          resolvePassword = resolve;
        }),
    );
    const queryClient = await renderApp();
    await waitForLoginQueries(queryClient);
    await waitForUI(() =>
      expect(findButton(container, "Corporate OIDC")).not.toBeNull(),
    );

    await setInput(
      container.querySelector('input[autocomplete="username"]'),
      "admin",
    );
    await setInput(
      container.querySelector('input[autocomplete="current-password"]'),
      "secret-password",
    );
    const signIn = findButton(container, "登录");
    const provider = findButton(container, "Corporate OIDC");
    await act(async () => {
      signIn?.click();
      provider?.click();
    });

    expect(loginWithPassword).toHaveBeenCalledOnce();
    expect(loginWithProvider).not.toHaveBeenCalled();
    expect(provider?.disabled).toBe(true);

    await act(async () =>
      resolvePassword({ accessToken: "password-token", user: principal }),
    );
    await waitForUI(() => expect(container.textContent).toContain("首页"));
  });

  it("hides password fields when local login is disabled and keeps enabled providers", async () => {
    vi.mocked(restoreSession).mockResolvedValueOnce(null);
    vi.mocked(getLoginOptions).mockResolvedValueOnce({
      localPasswordLoginEnabled: false,
      verification: { sliderEnabled: false },
    });
    vi.mocked(getAuthProviders).mockResolvedValueOnce([
      { id: "oidc-main", type: "oidc", name: "Corporate OIDC", enabled: true },
      {
        id: "disabled",
        type: "oidc",
        name: "Disabled Provider",
        enabled: false,
      },
    ]);
    const queryClient = await renderApp();
    await waitForLoginQueries(queryClient);
    await waitForUI(() =>
      expect(container.textContent).toContain("此组织未启用本地密码登录"),
    );

    expect(
      container.querySelector('input[autocomplete="current-password"]'),
    ).toBeNull();
    expect(container.textContent).toContain("Corporate OIDC");
    expect(container.textContent).not.toContain("Disabled Provider");
  });

  it("cancels a pending provider login without creating a session", async () => {
    vi.mocked(restoreSession).mockResolvedValueOnce(null);
    vi.mocked(getAuthProviders).mockResolvedValueOnce([
      { id: "oidc-main", type: "oidc", name: "Corporate OIDC", enabled: true },
    ]);
    let providerSignal: AbortSignal | undefined;
    vi.mocked(loginWithProvider).mockImplementationOnce(
      (_providerId, signal) =>
        new Promise((_resolve, reject) => {
          providerSignal = signal;
          signal.addEventListener(
            "abort",
            () => reject(new DOMException("Aborted", "AbortError")),
            { once: true },
          );
        }),
    );
    const queryClient = await renderApp();
    await waitForLoginQueries(queryClient);

    await waitForUI(() =>
      expect(findButton(container, "Corporate OIDC")).not.toBeNull(),
    );
    const providerButton = findButton(container, "Corporate OIDC");
    expect(providerButton).not.toBeNull();
    await act(async () =>
      providerButton?.dispatchEvent(
        new MouseEvent("click", { bubbles: true, cancelable: true }),
      ),
    );
    expect(loginWithProvider).toHaveBeenCalledOnce();
    await waitForUI(() =>
      expect(container.textContent).toContain("正在完成组织登录"),
    );
    expect(providerSignal?.aborted).toBe(false);

    await act(async () => findButton(container, "取消")?.click());
    await act(async () => {
      await vi.waitFor(() => expect(providerSignal?.aborted).toBe(true));
      await vi.waitFor(() =>
        expect(findButton(container, "Corporate OIDC")).not.toBeNull(),
      );
    });
    expect(getBootstrap).not.toHaveBeenCalled();
    expect(useAppStore.getState().session).toBeNull();
  });

  it("uses native sidebar chrome and clears local session when icon logout fails remotely", async () => {
    vi.mocked(logoutServer).mockRejectedValueOnce(new Error("offline"));
    const queryClient = await renderAppToHome();
    queryClient.setQueryData(["private"], { secret: true });

    const footer = container.querySelector(".sidebar-footer");
    const logout =
      footer?.querySelector<HTMLButtonElement>(
        'button[aria-label="退出登录"]',
      ) ?? null;
    expect(container.querySelector(".brand")).toBeNull();
    expect(container.querySelector(".sidebar-drag-region")).not.toBeNull();
    expect(logout).not.toBeNull();
    expect(logout?.textContent).toBe("");
    expect(logout?.getAttribute("title")).toBe("退出登录");
    await act(async () => logout?.click());
    await act(async () => {
      await vi.waitFor(() => expect(getLoginOptions).toHaveBeenCalledOnce());
      await vi.waitFor(() => expect(getAuthProviders).toHaveBeenCalledOnce());
      await vi.waitFor(() =>
        expect(
          queryClient.getQueryState(["auth", "login-options"])?.status,
        ).toBe("success"),
      );
      await vi.waitFor(() =>
        expect(queryClient.getQueryState(["auth", "providers"])?.status).toBe(
          "success",
        ),
      );
    });

    expect(logoutServer).toHaveBeenCalledOnce();
    expect(clearHostSession).toHaveBeenCalledOnce();
    expect(useAppStore.getState().session).toBeNull();
    expect(useAppStore.getState().bootstrap).toBeNull();
    expect(queryClient.getQueryData(["private"])).toBeUndefined();
  });

  it("keeps the sidebar navigation at its full size", async () => {
    await renderAppToHome();

    const shell = container.querySelector(".desktop-shell");
    expect(shell?.hasAttribute("data-navigation-size")).toBe(false);
    expect(container.querySelector('button[aria-label="收起导航"]')).toBeNull();
    expect(
      container.querySelector(".nav-item > span:last-child")?.textContent,
    ).toBe("首页");
  });

  it("exposes network, VPN, and proxy as first-class desktop routes", async () => {
    await renderAppToHome();

    const labels = Array.from(
      container.querySelectorAll(".nav-item > span:last-child"),
    ).map((item) => item.textContent?.trim());
    expect(labels).toEqual(expect.arrayContaining(["网络连接", "VPN", "代理"]));

    for (const label of ["网络连接", "VPN", "代理"]) {
      await clickNavigation(label);
      await waitForUI(() =>
        expect(
          container.querySelector(".nav-item.active")?.textContent,
        ).toContain(label),
      );
      expect(container.querySelector(".page h1")?.textContent).toBe(label);
    }
    expect(container.textContent).toContain(
      "macOS 代理执行服务尚未随当前构建交付",
    );
    await clickNavigation("网络连接");
    await waitForUI(() =>
      expect(container.querySelector(".network-wifi-select")).not.toBeNull(),
    );
    expect(container.querySelector(".page-heading")).toBeNull();
    expect(container.querySelector(".network-medium-switch")).not.toBeNull();
    expect(container.querySelector(".network-wifi-select")).not.toBeNull();
    expect(container.querySelector(".network-connect-button")).not.toBeNull();
    expect(container.textContent).toContain("有线");
    expect(container.textContent).toContain("192.0.2.10");
    expect(container.textContent).toContain("192.0.2.1");
    await act(async () => useAppStore.getState().setNetworkConnection({ selectedWifiKey: JSON.stringify(["site-1", "Soha-Staff"]) }));
    expect(container.textContent).toContain("Soha-Staff");
    const autoConnectButton = container.querySelector<HTMLButtonElement>(".network-connect-button");
    expect(autoConnectButton?.disabled).toBe(true);
    expect(container.textContent).toContain("暂不支持自动连接，请在系统网络设置中连接");
    await act(async () => useAppStore.getState().setNetworkConnection({ wifiAutoConnect: true, wiredAutoConnect: true }));
    expect(autoConnectButton?.getAttribute("aria-pressed")).toBe("false");
    expect(container.textContent).not.toContain("自动连接已开启");
    await clickNavigation("VPN");
    await waitForUI(() =>
      expect(container.textContent).toContain("签名的 Network Extension"),
    );
    expect(getNetworkStatus).not.toHaveBeenCalled();
  });

  it("shows a foreground connection failure and recovers on retry", async () => {
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    });
    await act(async () => {
      root.render(
        <ConfigProvider>
          <AntApp>
            <QueryClientProvider client={queryClient}>
              <DesktopApp />
            </QueryClientProvider>
          </AntApp>
        </ConfigProvider>,
      );
    });
    await act(async () => {
      await vi.waitFor(() =>
        expect(
          container.querySelector(".connection-indicator.online"),
        ).not.toBeNull(),
      );
    });

    vi.mocked(checkServer).mockResolvedValueOnce({
      status: "offline",
      serverUrl: "https://soha.example.com",
      code: "server_unreachable",
    });
    await act(async () => {
      document.dispatchEvent(new Event("visibilitychange"));
    });
    await act(async () => {
      await vi.waitFor(() =>
        expect(
          container.querySelector(".connection-indicator.offline"),
        ).not.toBeNull(),
      );
    });
    expect(
      container.querySelector(".connection-indicator")?.textContent,
    ).toContain("无法连接服务");
    expect(
      container.querySelector(".status-band .connection-state.offline"),
    ).not.toBeNull();

    const retry = container.querySelector<HTMLButtonElement>(
      'button[aria-label="重试"]',
    );
    expect(retry).not.toBeNull();
    await act(async () => retry?.click());
    await act(async () => {
      await vi.waitFor(() =>
        expect(
          container.querySelector(".connection-indicator.online"),
        ).not.toBeNull(),
      );
    });
    expect(
      container.querySelector(".connection-indicator")?.textContent,
    ).toContain("已连接");
  });

  it("requests announcements only with permission and marks an unread item", async () => {
    vi.mocked(getBootstrap).mockResolvedValueOnce({
      ...bootstrap,
      permissionSnapshot: { permissionKeys: ["system.announcements.view"] },
    });
    vi.mocked(getAnnouncementInbox).mockResolvedValue({
      unreadCount: 1,
      items: [
        {
          id: "announcement-1",
          title: "Maintenance notice",
          summary: "Planned maintenance",
          level: "info",
          isRead: false,
        },
      ],
    });
    const queryClient = await renderAppToHome();
    await act(async () => {
      await vi.waitFor(
        () => expect(getAnnouncementInbox).toHaveBeenCalledWith(5),
        { timeout: 3_000 },
      );
      await vi.waitFor(
        () =>
          expect(
            queryClient.getQueryState(["announcements", "inbox"])?.status,
          ).toBe("success"),
        { timeout: 3_000 },
      );
    });
    await waitForUI(() =>
      expect(container.textContent).toContain("Maintenance notice"),
    );

    expect(getAnnouncementInbox).toHaveBeenCalledWith(5);
    const markRead = container.querySelector<HTMLButtonElement>(
      'button[aria-label="标记为已读: Maintenance notice"]',
    );
    expect(markRead).not.toBeNull();
    await act(async () => markRead?.click());
    await act(async () => {
      await vi.waitFor(() =>
        expect(vi.mocked(markAnnouncementRead).mock.calls[0]?.[0]).toBe(
          "announcement-1",
        ),
      );
    });
  });

  it("distinguishes and retries an unavailable announcement service", async () => {
    vi.mocked(getBootstrap).mockResolvedValueOnce({
      ...bootstrap,
      permissionSnapshot: { permissionKeys: ["system.announcements.view"] },
    });
    vi.mocked(getAnnouncementInbox)
      .mockRejectedValueOnce(
        new ApiError(
          503,
          "upstream_unavailable",
          "Try again later",
          "announcement-request",
        ),
      )
      .mockResolvedValueOnce({ items: [], unreadCount: 0 });
    const queryClient = await renderAppToHome();

    await act(async () => {
      await vi.waitFor(
        () =>
          expect(
            queryClient.getQueryState(["announcements", "inbox"])?.status,
          ).toBe("error"),
        { timeout: 3_000 },
      );
    });
    await waitForUI(() =>
      expect(container.textContent).toContain("公告服务暂时不可用"),
    );
    expect(container.textContent).toContain("请求 ID: announcement-request");

    await act(async () => findButton(container, "重试")?.click());
    await act(async () => {
      await vi.waitFor(() =>
        expect(getAnnouncementInbox).toHaveBeenCalledTimes(2),
      );
      await vi.waitFor(() =>
        expect(
          queryClient.getQueryState(["announcements", "inbox"])?.status,
        ).toBe("success"),
      );
    });
    await waitForUI(() => expect(container.textContent).toContain("暂无公告"));
  });

  it("retries a failed profile and keeps external identities out of the password form", async () => {
    let rejectProfile: ((reason?: unknown) => void) | undefined;
    let resolveProfile:
      ((profile: Awaited<ReturnType<typeof getProfile>>) => void) | undefined;
    const externalProfile = {
      userId: "user-1",
      username: "admin",
      displayName: "Admin",
      email: "admin@soha.local",
      status: "active",
      roles: [],
      teams: [],
      projects: [],
      tags: [],
      identities: [
        {
          providerType: "oidc",
          providerId: "corp-oidc",
          displayName: "Corporate OIDC",
        },
      ],
    };
    vi.mocked(getProfile)
      .mockImplementationOnce(
        () =>
          new Promise((_, reject) => {
            rejectProfile = reject;
          }),
      )
      .mockImplementationOnce(
        () =>
          new Promise((resolve) => {
            resolveProfile = resolve;
          }),
      );
    const queryClient = await renderAppToHome();

    await clickNavigation("个人资料");
    await act(async () => {
      await vi.waitFor(() => expect(getProfile).toHaveBeenCalledTimes(1));
      expect(rejectProfile).toBeTypeOf("function");
      rejectProfile?.(new Error("offline"));
      await vi.waitFor(() =>
        expect(queryClient.getQueryState(["auth", "profile"])?.status).toBe(
          "error",
        ),
      );
    });
    await act(async () => {
      await vi.waitFor(() =>
        expect(container.textContent).toContain("无法连接服务"),
      );
    });
    await act(async () => {
      await vi.waitFor(() =>
        expect(findButton(container, "重试")).not.toBeNull(),
      );
    });
    const retry = findButton(container, "重试");
    await act(async () =>
      retry?.dispatchEvent(
        new MouseEvent("click", { bubbles: true, cancelable: true }),
      ),
    );
    await act(async () => {
      await vi.waitFor(() => expect(getProfile).toHaveBeenCalledTimes(2));
      expect(resolveProfile).toBeTypeOf("function");
      resolveProfile?.(externalProfile);
      await vi.waitFor(() =>
        expect(queryClient.getQueryState(["auth", "profile"])?.status).toBe(
          "success",
        ),
      );
    });
    await act(async () => {
      await vi.waitFor(() =>
        expect(container.textContent).toContain("Corporate OIDC"),
      );
    });

    expect(container.textContent).toContain("此账号没有本地密码身份");
    expect(
      container.querySelector('input[autocomplete="current-password"]'),
    ).toBeNull();
  });

  it("updates only editable profile fields and changes a local password", async () => {
    const profile = {
      userId: "user-1",
      username: "admin",
      displayName: "Admin",
      email: "admin@soha.local",
      phone: "13800000000",
      avatarUrl: "https://example.com/avatar.png",
      avatarFit: "contain",
      status: "active",
      roles: ["admin"],
      teams: [],
      projects: [],
      tags: [],
      identities: [
        {
          providerType: "password",
          providerId: "local",
          displayName: "Password",
        },
      ],
    };
    const updated = { ...profile, displayName: "Updated Admin" };
    vi.mocked(getProfile).mockResolvedValue(profile);
    vi.mocked(updateProfile).mockResolvedValueOnce(updated);
    const queryClient = await renderAppToHome();
    await clickNavigation("个人资料");
    await act(async () => {
      await vi.waitFor(
        () =>
          expect(queryClient.getQueryState(["auth", "profile"])?.status).toBe(
            "success",
          ),
        { timeout: 3_000 },
      );
    });
    await waitForUI(() =>
      expect(
        container.querySelector('input[autocomplete="name"]'),
      ).not.toBeNull(),
    );
    expect(container.textContent).toContain("完整显示");

    await setInput(
      container.querySelector('input[autocomplete="name"]'),
      updated.displayName,
    );
    await act(async () => findButton(container, "保存")?.click());
    await act(async () => {
      await vi.waitFor(() => expect(updateProfile).toHaveBeenCalledOnce());
    });
    expect(vi.mocked(updateProfile).mock.calls[0]?.[0]).toEqual({
      displayName: updated.displayName,
      email: profile.email,
      phone: profile.phone,
      avatarUrl: profile.avatarUrl,
      avatarFit: profile.avatarFit,
    });
    expect(useAppStore.getState().session?.user.displayName).toBe(
      updated.displayName,
    );

    await setInput(
      container.querySelector('input[autocomplete="current-password"]'),
      "current-secret",
    );
    const newPasswordInputs = container.querySelectorAll<HTMLInputElement>(
      'input[autocomplete="new-password"]',
    );
    await setInput(newPasswordInputs.item(0), "new-password");
    await setInput(newPasswordInputs.item(1), "different-password");
    await act(async () => findButton(container, "修改密码")?.click());
    await act(async () => {
      await vi.waitFor(() =>
        expect(document.body.textContent).toContain("两次输入的新密码不一致"),
      );
    });
    expect(changePassword).not.toHaveBeenCalled();

    await setInput(newPasswordInputs.item(1), "new-password");
    await act(async () => findButton(container, "修改密码")?.click());
    await act(async () => {
      await vi.waitFor(() =>
        expect(changePassword).toHaveBeenCalledWith(
          "current-secret",
          "new-password",
        ),
      );
    });
    await act(async () => {
      await vi.waitFor(() =>
        expect(
          container.querySelector<HTMLInputElement>(
            'input[autocomplete="current-password"]',
          )?.value,
        ).toBe(""),
      );
    });
  });

  it("keeps the current session when a new Server fails validation", async () => {
    await renderAppToHome();
    await clickNavigation("设置");
    vi.mocked(checkServer).mockResolvedValueOnce({
      status: "offline",
      serverUrl: "https://new-soha.example.com",
      code: "server_unreachable",
    });

    await act(async () => {
      await vi.waitFor(() =>
        expect(findButton(container, "编辑连接")).not.toBeNull(),
      );
    });
    const changeServer = findButton(container, "编辑连接");
    await act(async () => changeServer?.click());
    await act(async () => {
      await vi.waitFor(() =>
        expect(document.querySelector(".ant-modal input")).not.toBeNull(),
      );
    });
    const input = document.querySelector<HTMLInputElement>(".ant-modal input");
    await act(async () => {
      const setValue = Object.getOwnPropertyDescriptor(
        HTMLInputElement.prototype,
        "value",
      )?.set;
      setValue?.call(input, "https://new-soha.example.com");
      input?.dispatchEvent(new Event("input", { bubbles: true }));
    });
    const confirm = document.querySelector<HTMLButtonElement>(
      ".ant-modal .ant-btn-primary",
    );
    expect(confirm).not.toBeNull();
    await act(async () => confirm?.click());
    await act(async () => {
      await vi.waitFor(() =>
        expect(document.body.textContent).toContain(
          "确认服务已启动且网络可达后重试",
        ),
      );
    });

    expect(prepareServerSwitch).not.toHaveBeenCalled();
    expect(useAppStore.getState().session?.user.userId).toBe("user-1");
  });

  it("clears the old session before activating a validated Server switch", async () => {
    const queryClient = await renderAppToHome();
    queryClient.setQueryData(["private"], { secret: true });
    await clickNavigation("设置");
    const nextConnection = {
      status: "online" as const,
      serverUrl: "https://new-soha.example.com",
    };
    vi.mocked(checkServer).mockResolvedValueOnce(nextConnection);
    vi.mocked(prepareServerSwitch).mockResolvedValueOnce({
      activationToken: "activate-new-server",
      connection: nextConnection,
    });
    vi.mocked(activateServerSwitch).mockResolvedValueOnce({
      ...hostState,
      serverUrl: nextConnection.serverUrl,
      configurationSource: "runtime",
    });

    await act(async () => {
      await vi.waitFor(() =>
        expect(findButton(container, "编辑连接")).not.toBeNull(),
      );
    });
    await act(async () => findButton(container, "编辑连接")?.click());
    await act(async () => {
      await vi.waitFor(() =>
        expect(document.querySelector(".ant-modal input")).not.toBeNull(),
      );
    });
    await setInput(
      document.querySelector(".ant-modal input"),
      nextConnection.serverUrl,
    );
    await waitForUI(() => {
      expect(document.body.textContent).toContain(hostState.serverUrl);
      expect(document.body.textContent).toContain(nextConnection.serverUrl);
      expect(document.body.textContent).toContain("新服务器");
    });
    const confirm = document.querySelector<HTMLButtonElement>(
      ".ant-modal .ant-btn-primary",
    );
    await act(async () => confirm?.click());
    await act(async () => {
      await vi.waitFor(() =>
        expect(activateServerSwitch).toHaveBeenCalledOnce(),
      );
      await vi.waitFor(() => expect(getLoginOptions).toHaveBeenCalledOnce());
      await vi.waitFor(() => expect(getAuthProviders).toHaveBeenCalledOnce());
      await vi.waitFor(() =>
        expect(
          queryClient.getQueryState(["auth", "login-options"])?.status,
        ).toBe("success"),
      );
      await vi.waitFor(() =>
        expect(queryClient.getQueryState(["auth", "providers"])?.status).toBe(
          "success",
        ),
      );
    });

    expect(prepareServerSwitch).toHaveBeenCalledWith(
      nextConnection.serverUrl,
      "access-token",
    );
    expect(activateServerSwitch).toHaveBeenCalledWith("activate-new-server");
    expect(useAppStore.getState().host?.serverUrl).toBe(
      nextConnection.serverUrl,
    );
    expect(useAppStore.getState().session).toBeNull();
    expect(queryClient.getQueryData(["private"])).toBeUndefined();
  });

  it("keeps old credentials cleared when Server activation fails", async () => {
    const queryClient = await renderAppToHome();
    queryClient.setQueryData(["private"], { secret: true });
    await clickNavigation("设置");
    const nextConnection = {
      status: "online" as const,
      serverUrl: "https://new-soha.example.com",
    };
    vi.mocked(checkServer)
      .mockResolvedValueOnce(nextConnection)
      .mockResolvedValueOnce({
        status: "online",
        serverUrl: hostState.serverUrl,
      });
    vi.mocked(prepareServerSwitch).mockResolvedValueOnce({
      activationToken: "activate-new-server",
      connection: nextConnection,
    });
    vi.mocked(activateServerSwitch).mockRejectedValueOnce(
      new Error("activation failed"),
    );

    await act(async () => findButton(container, "编辑连接")?.click());
    await waitForUI(() =>
      expect(document.querySelector(".ant-modal input")).not.toBeNull(),
    );
    await setInput(
      document.querySelector(".ant-modal input"),
      nextConnection.serverUrl,
    );
    await act(async () =>
      document
        .querySelector<HTMLButtonElement>(".ant-modal .ant-btn-primary")
        ?.click(),
    );
    await waitForUI(() => expect(container.textContent).toContain("登录 Soha"));

    expect(getHostState).toHaveBeenCalledTimes(2);
    expect(useAppStore.getState().host?.serverUrl).toBe(hostState.serverUrl);
    expect(useAppStore.getState().session).toBeNull();
    expect(queryClient.getQueryData(["private"])).toBeUndefined();
  });

  it("provides a skip link and moves focus to main content after navigation", async () => {
    await renderAppToHome();
    const skipLink = container.querySelector<HTMLAnchorElement>("a.skip-link");
    const main = container.querySelector<HTMLElement>("#main-content");

    expect(skipLink?.getAttribute("href")).toMatch(/#main-content$/);
    expect(skipLink?.textContent).toBe("跳到主内容");
    expect(main?.getAttribute("tabindex")).toBe("-1");

    await clickNavigation("个人资料");
    await waitForUI(() =>
      expect(container.querySelector(".page > h1")?.textContent).toBe(
        "个人资料",
      ),
    );

    expect(document.activeElement).toBe(main);
  });

  it("keeps page names accessible without repeating navigation headings", async () => {
    await renderAppToHome();

    for (const pageName of ["个人资料", "设置", "软件库"]) {
      await clickNavigation(pageName);
      await waitForUI(() =>
        expect(container.querySelector(".page > h1")?.textContent).toBe(
          pageName,
        ),
      );
      expect(
        container
          .querySelector(".page > h1")
          ?.classList.contains("visually-hidden"),
      ).toBe(true);
      expect(container.querySelector(".page-heading")).toBeNull();
    }
  });

  it("keeps a managed Server fixed, persists appearance preferences, and reports updates unavailable", async () => {
    vi.mocked(getHostState).mockResolvedValueOnce({
      ...hostState,
      configurationSource: "environment",
      managedByEnvironment: true,
    });
    await renderAppToHome();
    await clickNavigation("设置");
    await act(async () => {
      await vi.waitFor(() =>
        expect(container.textContent).toContain("环境变量管理"),
      );
    });

    expect(findButton(container, "编辑连接")).toBeNull();
    expect(container.textContent).toContain("连接服务器");
    expect(container.textContent).toContain("当前构建未配置签名更新源");
    expect(findButton(container, "检查更新")?.disabled).toBe(true);
    expect(findButton(container, "配置同步")?.disabled).toBe(true);
    expect(
      findButton(container, "检查更新")?.closest(".ant-descriptions"),
    ).toBeNull();
    expect(
      Array.from(container.querySelectorAll(".ant-segmented-item")).map(
        (item) => item.textContent?.trim(),
      ),
    ).toEqual(
      expect.arrayContaining(["跟随系统", "浅色", "深色", "标准", "紧凑"]),
    );
    await clickSegmentedOption("深色");
    await clickSegmentedOption("紧凑");
    await clickSegmentedOption("English");
    await act(async () => {
      await vi.waitFor(() =>
        expect(useAppStore.getState().themeMode).toBe("dark"),
      );
      await vi.waitFor(() =>
        expect(useAppStore.getState().locale).toBe("en_US"),
      );
      await vi.waitFor(() =>
        expect(useAppStore.getState().portalCardSize).toBe("compact"),
      );
    });
    expect(container.textContent).toContain("Appearance and language");
    expect(container.textContent).toContain("Connected server");
    expect(container.textContent).not.toContain("外观与语言");
    await clickNavigation("Home");
    await waitForUI(() =>
      expect(container.textContent).toContain(
        "Review the current server status",
      ),
    );
    expect(container.textContent).not.toContain("查看当前服务状态");
    await clickNavigation("Profile");
    await waitForUI(() =>
      expect(container.querySelector(".page > h1")?.textContent).toBe(
        "Profile",
      ),
    );
    expect(container.textContent).not.toContain("View and update your profile");
    expect(container.textContent).not.toContain("查看和更新你的个人资料");
    const persisted = localStorage.getItem("soha-app-preferences") || "";
    expect(persisted).toContain("dark");
    expect(persisted).toContain("en_US");
    expect(persisted).toContain("compact");
  });

  it("connects and disconnects the Windows network service without exposing enrollment data", async () => {
    vi.mocked(getHostState).mockResolvedValueOnce({
      ...hostState,
      app: { ...hostState.app, platform: "windows", arch: "amd64" },
    });

    await renderAppToHome();
    await clickNavigation("VPN");
    await waitForUI(() => expect(container.textContent).toContain("未连接"));
    await setInput(
      container.querySelector<HTMLInputElement>("#siteId"),
      "site-1",
    );
    await setInput(
      container.querySelector<HTMLInputElement>("#networkSpaceId"),
      "space-1",
    );
    await setInput(
      container.querySelector<HTMLInputElement>("#gatewayId"),
      "gateway-b",
    );
    await act(async () => findButton(container, "连接内网")?.click());

    await waitForUI(() =>
      expect(connectNetwork).toHaveBeenCalledWith({
        siteId: "site-1",
        networkSpaceId: "space-1",
        gatewayId: "gateway-b",
        mode: "external_vpn",
        resourceIds: [],
      }),
    );
    expect(container.textContent).toContain("已连接");
    expect(container.textContent).not.toContain("enrollment");
    await act(async () => findButton(container, "断开连接")?.click());
    await waitForUI(() => expect(disconnectNetwork).toHaveBeenCalledOnce());
  });

  it("configures an App-owned mihomo subscription without retaining its URL", async () => {
    const subscriptionUrl =
      "https://subscriptions.example.test/private?token=secret";
    vi.mocked(getHostState).mockResolvedValueOnce({
      ...hostState,
      app: { ...hostState.app, platform: "windows", arch: "amd64" },
    });
    vi.mocked(getNetworkStatus).mockResolvedValueOnce({
      ...disconnectedNetworkStatus,
      state: "connected",
      mihomoMode: "app_subscription",
      mihomoProfileId: "mihomo-1",
      mihomoProfileRevision: 1,
    });

    await renderAppToHome();
    await clickNavigation("代理");
    await waitForUI(() =>
      expect(container.textContent).toContain("尚未配置订阅"),
    );
    const input = container.querySelector<HTMLInputElement>("#subscriptionUrl");
    await setInput(input, subscriptionUrl);
    await act(async () => findButton(container, "保存并加载订阅")?.click());

    await waitForUI(() =>
      expect(configureMihomoApp).toHaveBeenCalledWith(subscriptionUrl),
    );
    await waitForUI(() =>
      expect(
        container.querySelector<HTMLInputElement>("#subscriptionUrl")?.value,
      ).toBe(""),
    );
    expect(container.textContent).not.toContain(subscriptionUrl);
  });

  it("checks for updates once while a request is pending and reports success", async () => {
    let resolveCheck:
      ((result: typeof disabledUpdateStatus) => void) | undefined;
    vi.mocked(getHostState).mockResolvedValueOnce({
      ...hostState,
      app: { ...hostState.app, updateSupported: true, updateState: "idle" },
    });
    vi.mocked(getUpdateStatus).mockResolvedValueOnce({
      ...disabledUpdateStatus,
      supported: true,
      installMode: "self",
      state: "idle",
    });
    vi.mocked(checkForUpdates).mockReturnValueOnce(
      new Promise((resolve) => {
        resolveCheck = resolve;
      }),
    );

    await renderAppToHome();
    await clickNavigation("设置");
    const checkButton = findButton(container, "检查更新");
    expect(checkButton?.classList.contains("ant-btn-sm")).toBe(false);
    expect(checkButton?.closest(".ant-descriptions")).toBeNull();
    expect(
      checkButton
        ?.closest(".ant-space")
        ?.contains(findButton(container, "打开日志目录") || null),
    ).toBe(true);
    expect(
      checkButton
        ?.closest(".ant-space")
        ?.contains(findButton(container, "配置同步") || null),
    ).toBe(true);
    await act(async () => checkButton?.click());
    await waitForUI(() => expect(checkButton?.disabled).toBe(true));
    checkButton?.click();

    expect(checkForUpdates).toHaveBeenCalledOnce();
    expect(installUpdate).not.toHaveBeenCalled();
    await act(async () => resolveCheck?.(disabledUpdateStatus));
    await waitForUI(() =>
      expect(document.body.textContent).toContain("当前已是最新版本"),
    );
  });

  it("shows an update banner and installs only after the user clicks", async () => {
    vi.mocked(getHostState).mockResolvedValueOnce({
      ...hostState,
      app: { ...hostState.app, updateSupported: true, updateState: "idle" },
    });
    vi.mocked(getUpdateStatus).mockResolvedValue(availableUpdateStatus);
    vi.mocked(installUpdate).mockResolvedValue({
      ...availableUpdateStatus,
      state: "ready",
    });

    await renderAppToHome();
    await waitForUI(() =>
      expect(container.textContent).toContain("发现新版本 0.2.1"),
    );
    expect(
      container.querySelector(".nav-update-badge .ant-badge-dot"),
    ).not.toBeNull();
    expect(installUpdate).not.toHaveBeenCalled();

    await act(async () => findButton(container, "立即更新")?.click());
    await waitForUI(() => expect(installUpdate).toHaveBeenCalledOnce());
    expect(checkForUpdates).not.toHaveBeenCalled();

    await waitForUI(() =>
      expect(container.textContent).not.toContain("发现新版本 0.2.1"),
    );
    expect(
      container.querySelector(".nav-update-badge .ant-badge-dot"),
    ).toBeNull();
  });

  it("dismisses the update banner for the current session", async () => {
    vi.mocked(getHostState).mockResolvedValueOnce({
      ...hostState,
      app: { ...hostState.app, updateSupported: true, updateState: "idle" },
    });
    vi.mocked(getUpdateStatus).mockResolvedValue(availableUpdateStatus);

    await renderAppToHome();
    await waitForUI(() =>
      expect(container.textContent).toContain("发现新版本 0.2.1"),
    );

    const close = container.querySelector<HTMLButtonElement>(
      ".update-banner .ant-alert-close-icon",
    );
    expect(close).not.toBeNull();
    await act(async () => close?.click());
    expect(container.textContent).not.toContain("发现新版本 0.2.1");
  });

  it("does not offer an install action for a disabled update target", async () => {
    vi.mocked(getHostState).mockResolvedValueOnce({
      ...hostState,
      app: { ...hostState.app, updateSupported: true, updateState: "idle" },
    });
    vi.mocked(getUpdateStatus).mockResolvedValue({
      ...availableUpdateStatus,
      installMode: "disabled",
    });

    await renderAppToHome();
    await waitForUI(() =>
      expect(container.textContent).toContain("发现新版本 0.2.1"),
    );
    expect(findButton(container, "立即更新")).toBeNull();
    expect(findButton(container, "查看发布页")).toBeNull();
    expect(installUpdate).not.toHaveBeenCalled();
  });

  it("opens the release page for external updates without starting installation", async () => {
    const external = {
      ...availableUpdateStatus,
      installMode: "external" as const,
      downloadMode: "full" as const,
    };
    vi.mocked(getHostState).mockResolvedValueOnce({
      ...hostState,
      app: {
        ...hostState.app,
        platform: "linux",
        arch: "amd64",
        updateSupported: true,
        updateState: "idle",
      },
    });
    vi.mocked(getUpdateStatus).mockResolvedValue(external);

    await renderAppToHome();
    await waitForUI(() =>
      expect(container.textContent).toContain("发现新版本 0.2.1"),
    );
    await act(async () => findButton(container, "查看发布页")?.click());

    expect(openBrowserURL).toHaveBeenCalledWith(external.releaseURL);
    expect(installUpdate).not.toHaveBeenCalled();
  });

  it("reports update check errors with the Host request ID", async () => {
    vi.mocked(getHostState).mockResolvedValueOnce({
      ...hostState,
      app: { ...hostState.app, updateSupported: true, updateState: "idle" },
    });
    vi.mocked(getUpdateStatus).mockResolvedValueOnce({
      ...disabledUpdateStatus,
      supported: true,
      installMode: "self",
      state: "idle",
    });
    vi.mocked(checkForUpdates).mockRejectedValueOnce(
      new HostError(
        502,
        "update_check_failed",
        "更新服务不可用",
        "update-request-502",
      ),
    );

    await renderAppToHome();
    await clickNavigation("设置");
    await act(async () => findButton(container, "检查更新")?.click());

    await waitForUI(() =>
      expect(document.body.textContent).toContain(
        "更新服务不可用 (请求 ID: update-request-502)",
      ),
    );
  });

  it("lists compatible software and cancels before starting an install", async () => {
    vi.mocked(listSoftware).mockResolvedValueOnce({ items: [softwarePackage] });

    await renderAppToHome();
    await clickNavigation("软件库");
    await waitForUI(() =>
      expect(container.textContent).toContain("Soha Agent"),
    );

    expect(listSoftware).toHaveBeenCalledWith("access-token");
    expect(container.textContent).toContain("OpenSoha");
    expect(container.textContent).toContain("1.2.3");
    expect(container.textContent).toContain("适用于当前设备");
    await act(async () => findButton(container, "安装")?.click());
    await waitForUI(() =>
      expect(document.querySelector(".ant-modal")).not.toBeNull(),
    );
    expect(document.querySelector(".ant-modal")?.textContent).toContain(
      "下载、校验并打开系统安装器",
    );
    expect(document.querySelector(".ant-modal")?.textContent).toContain(
      "不会静默安装或提权",
    );
    await act(async () =>
      findButton(document.querySelector(".ant-modal")!, "取消")?.click(),
    );

    expect(installSoftware).not.toHaveBeenCalled();
  });

  it("shows an empty state when no software matches the current device", async () => {
    await renderAppToHome();
    await clickNavigation("软件库");

    await waitForUI(() =>
      expect(container.textContent).toContain("当前没有适用于此设备的软件"),
    );
  });

  it("retries an unavailable software catalog", async () => {
    vi.mocked(listSoftware)
      .mockRejectedValueOnce(
        new HostError(503, "catalog_unavailable", "软件目录暂不可用"),
      )
      .mockResolvedValueOnce({ items: [softwarePackage] });

    await renderAppToHome();
    await clickNavigation("软件库");
    await waitForUI(() =>
      expect(container.textContent).toContain("软件目录暂不可用"),
    );
    await act(async () => findButton(container, "重试")?.click());

    await waitForUI(() =>
      expect(container.textContent).toContain("Soha Agent"),
    );
    expect(listSoftware).toHaveBeenCalledTimes(2);
  });

  it("confirms an install, reports progress, and stops polling when completed", async () => {
    vi.mocked(listSoftware).mockResolvedValueOnce({ items: [softwarePackage] });
    vi.mocked(getSoftwareTask)
      .mockResolvedValueOnce({
        task: {
          ...queuedSoftwareTask,
          state: "downloading",
          progress: 42,
          message: "正在下载安装包",
        },
      })
      .mockResolvedValueOnce({
        task: {
          ...queuedSoftwareTask,
          state: "completed",
          progress: 100,
          message: "安装器已打开",
        },
      });

    await renderAppToHome();
    await clickNavigation("软件库");
    await waitForUI(() =>
      expect(container.textContent).toContain("Soha Agent"),
    );
    await act(async () => findButton(container, "安装")?.click());
    await waitForUI(() =>
      expect(document.querySelector(".ant-modal")).not.toBeNull(),
    );
    await act(async () =>
      document
        .querySelector<HTMLButtonElement>(".ant-modal .ant-btn-primary")
        ?.click(),
    );

    expect(installSoftware).toHaveBeenCalledWith("soha-agent", "access-token");
    await waitForUI(() =>
      expect(
        container.querySelector(".ant-progress")?.getAttribute("aria-valuenow"),
      ).toBe("42"),
    );
    await act(async () => new Promise((resolve) => setTimeout(resolve, 300)));
    expect(container.textContent).toContain("安装器已打开");
    const completedCalls = vi.mocked(getSoftwareTask).mock.calls.length;
    await act(async () => new Promise((resolve) => setTimeout(resolve, 350)));
    expect(getSoftwareTask).toHaveBeenCalledTimes(completedCalls);
  });

  it("shows a failed install task without continuing to poll", async () => {
    vi.mocked(listSoftware).mockResolvedValueOnce({ items: [softwarePackage] });
    vi.mocked(getSoftwareTask).mockResolvedValueOnce({
      task: {
        ...queuedSoftwareTask,
        state: "failed",
        message: "安装包下载或校验失败",
      },
    });

    await renderAppToHome();
    await clickNavigation("软件库");
    await waitForUI(() =>
      expect(container.textContent).toContain("Soha Agent"),
    );
    await act(async () => findButton(container, "安装")?.click());
    await waitForUI(() =>
      expect(document.querySelector(".ant-modal")).not.toBeNull(),
    );
    await act(async () =>
      document
        .querySelector<HTMLButtonElement>(".ant-modal .ant-btn-primary")
        ?.click(),
    );

    await waitForUI(() =>
      expect(container.textContent).toContain("安装包下载或校验失败"),
    );
    expect(
      container.querySelector(".ant-progress")?.getAttribute("aria-label"),
    ).toBe("安装失败");
    expect(getSoftwareTask).toHaveBeenCalledOnce();
  });
});

async function renderAppToHome() {
  const queryClient = await renderApp();
  await act(async () => {
    await vi.waitFor(() => expect(container.textContent).toContain("首页"), {
      timeout: 3_000,
    });
  });
  return queryClient;
}

async function renderApp(initialEntries?: string[]) {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  await act(async () => {
    root.render(
      <ConfigProvider>
        <AntApp>
          <QueryClientProvider client={queryClient}>
            <DesktopApp initialEntries={initialEntries} />
          </QueryClientProvider>
        </AntApp>
      </ConfigProvider>,
    );
  });
  return queryClient;
}

async function waitForLoginQueries(queryClient: QueryClient) {
  await act(async () => {
    await vi.waitFor(() => expect(getLoginOptions).toHaveBeenCalledOnce());
    await vi.waitFor(() => expect(getAuthProviders).toHaveBeenCalledOnce());
    await vi.waitFor(() =>
      expect(queryClient.getQueryState(["auth", "login-options"])?.status).toBe(
        "success",
      ),
    );
    await vi.waitFor(() =>
      expect(queryClient.getQueryState(["auth", "providers"])?.status).toBe(
        "success",
      ),
    );
  });
}

async function clickNavigation(label: string) {
  const link = Array.from(
    container.querySelectorAll<HTMLAnchorElement>("a"),
  ).find((candidate) => candidate.textContent?.trim() === label);
  expect(link).toBeDefined();
  await act(async () => link?.click());
}

async function clickSegmentedOption(label: string) {
  const option = Array.from(
    container.querySelectorAll<HTMLElement>(".ant-segmented-item"),
  ).find((candidate) => candidate.textContent?.trim() === label);
  expect(option).toBeDefined();
  await act(async () => option?.click());
}

async function waitForUI(assertion: () => void) {
  await vi.waitFor(
    async () => {
      await act(async () => {
        await new Promise((resolve) => setTimeout(resolve, 0));
      });
      assertion();
    },
    { timeout: 3_000 },
  );
}

function findButton(
  rootElement: ParentNode,
  label: string,
): HTMLButtonElement | null {
  const normalizedLabel = label.replace(/\s+/g, "");
  return (
    Array.from(rootElement.querySelectorAll<HTMLButtonElement>("button")).find(
      (button) =>
        button.textContent?.replace(/\s+/g, "").includes(normalizedLabel),
    ) || null
  );
}

async function setInput(input: HTMLInputElement | null, value: string) {
  expect(input).not.toBeNull();
  await act(async () => {
    const setValue = Object.getOwnPropertyDescriptor(
      HTMLInputElement.prototype,
      "value",
    )?.set;
    setValue?.call(input, value);
    input?.dispatchEvent(new Event("input", { bubbles: true }));
  });
}
