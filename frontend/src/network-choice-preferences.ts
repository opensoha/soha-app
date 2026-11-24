export interface NetworkChoicePreferences {
  preferred: string
  autoConnect: string[]
}

const emptyPreferences: NetworkChoicePreferences = { preferred: "", autoConnect: [] }
const storageKey = "soha-app-network-choice-preferences"

export function networkChoiceScope(serverUrl: string, deviceId: string, userId: string) {
  return serverUrl && deviceId && userId ? JSON.stringify([serverUrl, deviceId, userId]) : ""
}

export function readNetworkChoicePreferences(scope: string): NetworkChoicePreferences {
  if (!scope) return emptyPreferences
  try {
    const all = JSON.parse(localStorage.getItem(storageKey) || "{}") as Record<string, unknown>
    const value = all[scope]
    if (typeof value !== "object" || value === null) return emptyPreferences
    const record = value as Partial<NetworkChoicePreferences>
    return {
      preferred: typeof record.preferred === "string" ? record.preferred : "",
      autoConnect: Array.isArray(record.autoConnect)
        ? record.autoConnect.filter((key): key is string => typeof key === "string")
        : [],
    }
  } catch {
    return emptyPreferences
  }
}

export function writeNetworkChoicePreferences(scope: string, preferences: NetworkChoicePreferences) {
  if (!scope) return
  try {
    const all = JSON.parse(localStorage.getItem(storageKey) || "{}") as Record<string, unknown>
    all[scope] = preferences
    localStorage.setItem(storageKey, JSON.stringify(all))
  } catch {
    // Preferences are optional; storage may be unavailable.
  }
}

/** Drop choices not present in the latest authoritative option list. */
export function pruneNetworkChoicePreferences(scope: string, valid: string[]) {
  const current = readNetworkChoicePreferences(scope)
  const next: NetworkChoicePreferences = {
    preferred: valid.includes(current.preferred) ? current.preferred : "",
    autoConnect: current.autoConnect.filter((key) => valid.includes(key)),
  }
  if (next.preferred !== current.preferred || next.autoConnect.length !== current.autoConnect.length) {
    writeNetworkChoicePreferences(scope, next)
  }
  return next
}
