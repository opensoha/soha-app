export type StrictWifiOption = {
  ssid?: string;
  accessMedium: string;
  strictOnline?: { leaseUntil?: string };
};

export type StrictWifiLink = {
  known?: boolean;
  connected: boolean;
  medium?: string;
  openWifiSsid?: string;
  demo?: unknown;
};

const ISO_TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/;

export function canSwitchToStrictWifi(
  option: StrictWifiOption,
  link: StrictWifiLink,
  now: number,
): boolean {
  const targetSsid = option.ssid;
  const leaseUntil = option.strictOnline?.leaseUntil;
  if (option.accessMedium !== "wifi" || !targetSsid?.trim() || !leaseUntil || !ISO_TIMESTAMP.test(leaseUntil)) return false;
  const lease = Date.parse(leaseUntil);
  if (!Number.isFinite(lease) || lease - now < 5_000 || lease - now > 30_000) return false;
  // Open SSIDs can be reused at unrelated sites. Keep a live link until the
  // user selects the enterprise network or the App can verify its association.
  return link.known === true && !link.connected && !link.demo;
}
