import { describe, expect, it } from "vitest";
import { canSwitchToStrictWifi, type StrictWifiLink, type StrictWifiOption } from "./admission-continuity-policy";

const now = Date.parse("2026-11-22T10:00:00Z");
const lease = (seconds: number) => new Date(now + seconds * 1000).toISOString();
const option: StrictWifiOption = { ssid: "Strict", accessMedium: "wifi", strictOnline: { leaseUntil: lease(10) } };

describe("canSwitchToStrictWifi", () => {
  it.each<[string, StrictWifiLink, boolean]>([
    ["known disconnected", { known: true, connected: false }, true],
    ["connected on an open Wi-Fi with the configured guest SSID", { known: true, connected: true, medium: "wifi", openWifiSsid: "Guest" }, false],
    ["connected on target ssid", { known: true, connected: true, medium: "wifi", openWifiSsid: "Strict" }, false],
    ["connected on unknown ssid", { known: true, connected: true, medium: "wifi", openWifiSsid: "Other" }, false],
    ["connected on non-wifi medium", { known: true, connected: true, medium: "ethernet", openWifiSsid: "Guest" }, false],
    ["unknown link", { known: false, connected: false }, false],
    ["missing known flag", { connected: false }, false],
    ["demo link", { known: true, connected: false, demo: true }, false],
  ])("%s", (_name, link, expected) => {
    expect(canSwitchToStrictWifi(option, link, now)).toBe(expected);
  });

  it.each<[string, StrictWifiOption]>([
    ["empty ssid", { ...option, ssid: " " }],
    ["missing lease", { ...option, strictOnline: {} }],
    ["wired option", { ...option, accessMedium: "wired" }],
    ["non-iso lease", { ...option, strictOnline: { leaseUntil: "2026-11-22" } }],
    ["lease under 5s", { ...option, strictOnline: { leaseUntil: lease(4) } }],
    ["lease over 30s", { ...option, strictOnline: { leaseUntil: lease(31) } }],
  ])("rejects %s", (_name, candidate) => {
    expect(canSwitchToStrictWifi(candidate, { known: true, connected: false }, now)).toBe(false);
  });

  it("allows the 5s and 30s lease bounds", () => {
    expect(canSwitchToStrictWifi({ ...option, strictOnline: { leaseUntil: lease(5) } }, { known: true, connected: false }, now)).toBe(true);
    expect(canSwitchToStrictWifi({ ...option, strictOnline: { leaseUntil: lease(30) } }, { known: true, connected: false }, now)).toBe(true);
  });
});
