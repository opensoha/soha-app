import { beforeEach, describe, expect, it } from "vitest";
import { selectAssistantOwner, useAppStore } from "@/store";

describe("app preferences persistence", () => {
  beforeEach(() => {
    localStorage.clear();
    useAppStore.setState({
      host: null,
      connection: null,
      session: null,
      bootstrap: null,
      themeMode: "system",
      locale: "zh_CN",
      portalCardSize: "standard",
      networkConnection: {
        selectedWifiKey: "",
        wifiAutoConnect: false,
        wiredAutoConnect: false,
      },
    });
  });

  it("persists preferences without account or token data", () => {
    useAppStore.getState().commitSession({
      accessToken: "secret-access-token",
      user: {
        userId: "user-1",
        userName: "admin",
        email: "admin@soha.local",
        roles: [],
        teams: [],
        projects: [],
        tags: [],
      },
    });
    useAppStore.getState().setThemeMode("dark");
    useAppStore.getState().setLocale("en_US");
    useAppStore.getState().setPortalCardSize("compact");
    useAppStore
      .getState()
      .setNetworkConnection({
        selectedWifiKey: '["site-1","Soha-Staff"]',
        wifiAutoConnect: true,
      });

    const persisted = localStorage.getItem("soha-app-preferences") || "";
    expect(persisted).toContain("dark");
    expect(persisted).toContain("en_US");
    expect(persisted).toContain("compact");
    expect(persisted).toContain("Soha-Staff");
    expect(persisted).not.toContain("secret-access-token");
    expect(persisted).not.toContain("admin@soha.local");
  });

  it("isolates the same user ID on different servers", () => {
    const user = {
      userId: "same-user",
      userName: "user",
      email: "",
      roles: [],
      teams: [],
      projects: [],
      tags: [],
    };
    useAppStore.setState({
      bootstrap: {
        user,
        currentUser: user,
        permissionSnapshot: { permissionKeys: [] },
        branding: {},
      },
    });
    const current = useAppStore.getState();
    const first = selectAssistantOwner({
      ...current,
      host: { serverUrl: "https://first.example" } as NonNullable<
        typeof current.host
      >,
    });
    const second = selectAssistantOwner({
      ...current,
      host: { serverUrl: "https://second.example" } as NonNullable<
        typeof current.host
      >,
    });
    expect(first).not.toBe(second);
    expect(
      selectAssistantOwner({ ...current, bootstrap: null }),
    ).toBeUndefined();
  });

  it("drops the previous service identity and VPN grant state when the host changes", () => {
    const app = {
      name: "Soha",
      version: "fixture",
      platform: "darwin",
      arch: "arm64",
      logDirectory: "",
      updateSupported: false,
    };
    const first = {
      serverUrl: "https://first.example",
      configurationSource: "runtime" as const,
      managedByEnvironment: false,
      app,
    };
    useAppStore.getState().setHost(first);
    useAppStore
      .getState()
      .commitSession({
        accessToken: "fixture-only",
        user: {
          userId: "same-user",
          userName: "fixture",
          email: "",
          roles: [],
          teams: [],
          projects: [],
          tags: [],
        },
      });
    useAppStore.getState().setThemeMode("dark");
    useAppStore
      .getState()
      .setVPNRecovery({
        profileId: "old-profile",
        selection: "",
        max: 1,
        cooldown: 1,
        failures: 0,
        attempts: 0,
        nextAt: 0,
      });
    useAppStore
      .getState()
      .setHost({ ...first, serverUrl: "https://second.example" });
    expect(useAppStore.getState()).toMatchObject({
      session: null,
      bootstrap: null,
      connection: null,
      vpnRecovery: null,
      themeMode: "dark",
    });
    expect(selectAssistantOwner(useAppStore.getState())).toBeUndefined();
  });

  it("falls back when persisted preferences contain unsupported values", async () => {
    localStorage.setItem(
      "soha-app-preferences",
      JSON.stringify({
        state: { themeMode: "sepia", locale: "fr_FR", portalCardSize: "dense" },
        version: 1,
      }),
    );

    await useAppStore.persist.rehydrate();

    expect(useAppStore.getState().themeMode).toBe("system");
    expect(useAppStore.getState().locale).toBe("zh_CN");
    expect(useAppStore.getState().portalCardSize).toBe("standard");
    expect(useAppStore.getState().networkConnection).toEqual({
      selectedWifiKey: "",
      wifiAutoConnect: false,
      wiredAutoConnect: false,
    });
  });

  it("restores supported preferences from the persisted state envelope", async () => {
    localStorage.setItem(
      "soha-app-preferences",
      JSON.stringify({
        state: {
          themeMode: "dark",
          locale: "en_US",
          portalCardSize: "compact",
          networkConnection: {
            selectedWifiKey: '["site-1","Soha-Staff"]',
            wifiAutoConnect: true,
            wiredAutoConnect: true,
          },
        },
        version: 1,
      }),
    );

    await useAppStore.persist.rehydrate();

    expect(useAppStore.getState().themeMode).toBe("dark");
    expect(useAppStore.getState().locale).toBe("en_US");
    expect(useAppStore.getState().portalCardSize).toBe("compact");
    expect(useAppStore.getState().networkConnection).toEqual({
      selectedWifiKey: '["site-1","Soha-Staff"]',
      wifiAutoConnect: true,
      wiredAutoConnect: true,
    });
  });
});
