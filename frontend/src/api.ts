import type {
  NetworkVPNConnectionOption,
  NetworkVPNConnectionIntentInput,
  NetworkVPNConnectionIntentSecret,
  NetworkVPNConnectionView,
} from "@opensoha/contracts/gen/ts/sohaapi";
import type {
  Announcement,
  AnnouncementInbox,
  AuthProvider,
  Bootstrap,
  Branding,
  EndpointDeviceRegistrationInput,
  IdentityApplication,
  LinkedIdentity,
  LoginOptions,
  NetworkAccessGrantInput,
  NetworkAccessGrantSecret,
  NetworkConnectionOption,
  PortalBootstrap,
  PortalLaunchDecision,
  Principal,
  ProfileUpdate,
  Session,
  UserProfile,
} from "@/types";
import {
  startDesktopAuth,
  wailsRequestBodyHeader,
  savePersonalDataExport,
} from "@/native/host";

export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
    readonly requestId?: string,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

let accessToken: string | null = null;
let refreshInFlight: Promise<Session | null> | null = null;
type SessionListener = (session: Session | null, bootstrap?: Bootstrap) => void;
let sessionListener: SessionListener | null = null;
let sessionGeneration = 0;
const pendingRequests = new Set<AbortController>();
const responseGenerations = new WeakMap<Response, number>();

export function invalidateServerRequests(): void {
  sessionGeneration++;
  refreshInFlight = null;
  for (const controller of pendingRequests) controller.abort();
  pendingRequests.clear();
}

function assertCurrentSession(generation: number): void {
  if (generation !== sessionGeneration)
    throw new ApiError(0, "session_changed", "Soha server or session changed");
}

export function setAccessToken(token: string | null): void {
  if (token === null) invalidateServerRequests();
  accessToken = token;
}

export function setSessionListener(
  listener: SessionListener | null,
): void {
  sessionListener = listener;
}

export async function loginWithPassword(
  login: string,
  password: string,
): Promise<Session> {
  const generation = sessionGeneration;
  const payload = await request(
    "/auth/login",
    {
      method: "POST",
      body: JSON.stringify({ login, password }),
    },
    false,
    false,
  );
  assertCurrentSession(generation);
  const session = parseAuthSession(payload);
  setAccessToken(session.accessToken);
  return session;
}

export async function loginWithProvider(
  providerId: string,
  signal: AbortSignal,
): Promise<Session> {
  const generation = sessionGeneration;
  const session = parseAuthSessionData(
    await startDesktopAuth(providerId, signal),
  );
  assertCurrentSession(generation);
  setAccessToken(session.accessToken);
  return session;
}

export async function restoreSession(): Promise<Session | null> {
  const generation = sessionGeneration;
  try {
    const session = await refreshSession();
    assertCurrentSession(generation);
    if (session) setAccessToken(session.accessToken);
    return session;
  } catch (error) {
    assertCurrentSession(generation);
    if (
      error instanceof ApiError &&
      (error.status === 401 || error.status === 403)
    ) {
      setAccessToken(null);
      return null;
    }
    throw error;
  }
}

export async function getLoginOptions(): Promise<LoginOptions> {
  const payload = await request("/auth/login-options", {}, false, false);
  const data = envelopeData(payload);
  if (
    !isRecord(data) ||
    !isRecord(data.verification) ||
    typeof data.verification.sliderEnabled !== "boolean"
  ) {
    throw contractError();
  }
  return data as unknown as LoginOptions;
}

export async function getAuthProviders(): Promise<AuthProvider[]> {
  const payload = await request("/auth/providers", {}, false, false);
  if (!isRecord(payload)) throw contractError();
  const providers = Array.isArray(payload.items)
    ? payload.items
    : Array.isArray(payload.data)
      ? payload.data
      : null;
  if (!providers) throw contractError();
  return providers.filter(isAuthProvider);
}

export async function getBootstrap(): Promise<Bootstrap> {
  return readBootstrap(true);
}

async function readBootstrap(retryAfterRefresh: boolean): Promise<Bootstrap> {
  const payload = await request("/auth/bootstrap", {}, true, retryAfterRefresh);
  const data = envelopeData(payload);
  if (
    !isRecord(data) ||
    !isPrincipal(data.user) ||
    !isPrincipal(data.currentUser)
  ) {
    throw contractError();
  }
  const snapshot = isRecord(data.permissionSnapshot)
    ? data.permissionSnapshot
    : {};
  return {
    user: normalizePrincipal(data.user),
    currentUser: normalizePrincipal(data.currentUser),
    permissionSnapshot: {
      permissionKeys: stringArray(snapshot.permissionKeys),
    },
    branding: isRecord(data.branding) ? (data.branding as Branding) : {},
  };
}

export function registerEndpointDevice(
  deviceId: string,
  input: EndpointDeviceRegistrationInput,
): Promise<void> {
  return request(
    `/network-access/devices/${encodeURIComponent(deviceId)}/registration`,
    {
      method: "PUT",
      body: JSON.stringify(input),
    },
  ).then(() => undefined);
}

export async function getNetworkConnectionOptions(
  deviceId: string,
): Promise<NetworkConnectionOption[]> {
  const payload = await request(
    `/network-access/connection-options?deviceId=${encodeURIComponent(deviceId)}`,
  );
  if (
    !isRecord(payload) ||
    !Array.isArray(payload.items) ||
    !payload.items.every(isNetworkConnectionOption)
  ) {
    throw contractError();
  }
  return payload.items as NetworkConnectionOption[];
}

export async function getProfile(): Promise<UserProfile> {
  const payload = await request("/auth/profile");
  const data = envelopeData(payload);
  if (
    !isRecord(data) ||
    !hasStrings(data, ["userId", "username", "displayName", "email", "status"])
  ) {
    throw contractError();
  }
  return {
    userId: data.userId as string,
    username: data.username as string,
    displayName: data.displayName as string,
    email: data.email as string,
    phone: optionalString(data.phone),
    avatarUrl: optionalString(data.avatarUrl),
    avatarFit: optionalString(data.avatarFit),
    status: data.status as string,
    roles: stringArray(data.roles),
    teams: stringArray(data.teams),
    projects: stringArray(data.projects),
    tags: stringArray(data.tags),
    identities: Array.isArray(data.identities)
      ? data.identities
          .filter(isRecord)
          .map(normalizeIdentity)
          .filter((item): item is LinkedIdentity => item !== null)
      : [],
    lastLoginAt: optionalString(data.lastLoginAt),
  };
}

export async function updateProfile(
  input: ProfileUpdate,
): Promise<UserProfile> {
  const payload = await request("/auth/profile", {
    method: "PATCH",
    body: JSON.stringify(input),
  });
  const data = envelopeData(payload);
  if (
    !isRecord(data) ||
    !hasStrings(data, ["userId", "username", "displayName", "email", "status"])
  ) {
    throw contractError();
  }
  return getProfileFromData(data);
}

export function changePassword(
  currentPassword: string,
  newPassword: string,
): Promise<void> {
  return request("/auth/profile/password", {
    method: "POST",
    body: JSON.stringify({ currentPassword, newPassword }),
  }).then(() => undefined);
}

export function logoutServer(): Promise<void> {
  return request(
    "/auth/logout",
    { method: "POST", body: "{}" },
    true,
    false,
  ).then(() => undefined);
}

export async function getAnnouncementInbox(
  limit = 5,
): Promise<AnnouncementInbox> {
  const payload = await request(`/announcements/inbox?limit=${limit}`);
  const data = envelopeData(payload);
  if (
    !isRecord(data) ||
    !Array.isArray(data.items) ||
    typeof data.unreadCount !== "number"
  ) {
    throw contractError();
  }
  return {
    unreadCount: data.unreadCount,
    items: data.items
      .filter(isAnnouncement)
      .map((item) => item as unknown as Announcement),
  };
}

export function markAnnouncementRead(id: string): Promise<void> {
  return request(`/announcements/${encodeURIComponent(id)}/read`, {
    method: "POST",
    body: "{}",
  }).then(() => undefined);
}

export async function createNetworkAccessGrant(
  input: NetworkAccessGrantInput,
): Promise<NetworkAccessGrantSecret> {
  const data = envelopeData(
    await request("/network-access/access-grants", {
      method: "POST",
      body: JSON.stringify(input),
    }),
  );
  if (
    !isRecord(data) ||
    !isRecord(data.grant) ||
    typeof data.grant.id !== "string" ||
    typeof data.token !== "string" ||
    data.token.length < 32 ||
    data.token.length > 256
  ) {
    throw contractError();
  }
  return { grant: { id: data.grant.id }, token: data.token };
}

export async function getPortalBootstrap(): Promise<PortalBootstrap> {
  const data = envelopeData(await request("/portal/bootstrap"));
  if (!isPortalBootstrap(data)) throw contractError();
  return data as unknown as PortalBootstrap;
}

export async function getPortalApplication(
  id: string,
): Promise<IdentityApplication> {
  const data = envelopeData(
    await request(`/portal/applications/${encodeURIComponent(id)}`),
  );
  if (!isIdentityApplication(data)) throw contractError();
  return data as unknown as IdentityApplication;
}

export async function launchPortalApplication(
  id: string,
): Promise<PortalLaunchDecision> {
  const data = envelopeData(
    await request(`/portal/applications/${encodeURIComponent(id)}/launch`, {
      method: "POST",
      body: JSON.stringify({ surface: "desktop" }),
    }),
  );
  if (!isPortalLaunchDecision(data)) throw contractError();
  return data as unknown as PortalLaunchDecision;
}

export async function setPortalFavorite(
  id: string,
  favorite: boolean,
): Promise<IdentityApplication | undefined> {
  const path = `/portal/applications/${encodeURIComponent(id)}/favorite`;
  if (!favorite) {
    await request(path, { method: "DELETE" });
    return undefined;
  }
  const data = envelopeData(await request(path, { method: "POST" }));
  if (!isIdentityApplication(data)) throw contractError();
  return data as unknown as IdentityApplication;
}

async function request(
  path: string,
  init: RequestInit = {},
  authenticated = true,
  retryAfterRefresh = true,
): Promise<unknown> {
  const response = await requestResponse(
    path,
    init,
    authenticated,
    retryAfterRefresh,
  );
  return readPayload(response);
}

// Streaming callers share the same token refresh and Wails body transport.
export async function requestResponse(
  path: string,
  init: RequestInit = {},
  authenticated = true,
  retryAfterRefresh = true,
): Promise<Response> {
  const generation = sessionGeneration;
  const controller = new AbortController();
  const abort = () => controller.abort(init.signal?.reason);
  const release = () => {
    pendingRequests.delete(controller);
    init.signal?.removeEventListener("abort", abort);
  };
  pendingRequests.add(controller);
  init.signal?.addEventListener("abort", abort, { once: true });
  if (init.signal?.aborted) abort();
  const headers = new Headers(init.headers);
  if (!headers.has("Accept")) headers.set("Accept", "application/json");
  if (init.body != null && !headers.has("Content-Type"))
    headers.set("Content-Type", "application/json");
  if (authenticated && accessToken)
    headers.set("Authorization", `Bearer ${accessToken}`);
  const wailsBody =
    typeof init.body === "string" && isWailsAssetTransport() ? init.body : null;
  if (wailsBody !== null) {
    headers.set(wailsRequestBodyHeader, encodeURIComponent(wailsBody));
  }

  let response: Response;
  try {
    response = await fetch(`/api/v1${path}`, {
      ...init,
      signal: controller.signal,
      body: wailsBody === null ? init.body : undefined,
      headers,
      credentials: "include",
      redirect: "error",
    });
  } catch (error) {
    release();
    assertCurrentSession(generation);
    if (init.signal?.aborted) throw error;
    throw new ApiError(0, "network_error", "Soha server is unavailable");
  }

  try {
    assertCurrentSession(generation);
  } catch (error) {
    release();
    void response.body?.cancel().catch(() => undefined);
    throw error;
  }
  response = scopedResponse(response, generation, controller, release);

  if (response.status === 401 && authenticated && retryAfterRefresh) {
    const payload = await readPayload(response);
    const session = await singleFlightRefresh();
    if (session) {
      assertCurrentSession(generation);
      return requestResponse(path, init, authenticated, false);
    }
    throw responseError(response, payload);
  }

  if (!response.ok) throw responseError(response, await readPayload(response));
  return response;
}

// Guard the body as well as response headers: SSE may outlive a server switch.
function scopedResponse(
  response: Response,
  generation: number,
  controller: AbortController,
  release: () => void,
): Response {
  if (!response.body) {
    release();
    responseGenerations.set(response, generation);
    return response;
  }
  const reader = response.body.getReader();
  let closed = false;
  const finish = () => {
    closed = true;
    controller.signal.removeEventListener("abort", abort);
    release();
  };
  let output: ReadableStreamDefaultController<Uint8Array>;
  const abort = () => {
    if (closed) return;
    output.error(new DOMException("Request canceled", "AbortError"));
    void reader.cancel().catch(() => undefined);
    finish();
  };
  const body = new ReadableStream<Uint8Array>({
    start(stream) {
      output = stream;
      controller.signal.addEventListener("abort", abort, { once: true });
      if (controller.signal.aborted) abort();
    },
    async pull(stream) {
      try {
        assertCurrentSession(generation);
        const chunk = await reader.read();
        if (closed) return;
        assertCurrentSession(generation);
        if (chunk.done) {
          stream.close();
          finish();
        } else stream.enqueue(chunk.value);
      } catch (error) {
        if (!closed) {
          stream.error(error);
          void reader.cancel().catch(() => undefined);
          finish();
        }
      }
    },
    async cancel(reason) {
      finish();
      await reader.cancel(reason);
    },
  });
  const guarded = new Response(body, {
    status: response.status,
    statusText: response.statusText,
    headers: response.headers,
  });
  responseGenerations.set(guarded, generation);
  return guarded;
}

export async function assistantRequest<T>(
  path: string,
  init: RequestInit = {},
): Promise<T> {
  return envelopeData(await request(path, init)) as T;
}

function isWailsAssetTransport(): boolean {
  return (
    globalThis.location.protocol === "wails:" ||
    globalThis.location.hostname === "wails.localhost"
  );
}

export async function saveNativePersonalData(
  input: { assistantId: string; environmentVersion: number },
  signal: AbortSignal,
): Promise<"saved" | "canceled" | null> {
  if (!isWailsAssetTransport()) return null;
  const generation = sessionGeneration;
  const result = await savePersonalDataExport(input, accessToken, signal);
  assertCurrentSession(generation);
  if (result.status !== "saved" && result.status !== "canceled")
    throw contractError();
  return result.status;
}

async function singleFlightRefresh(): Promise<Session | null> {
  if (!refreshInFlight) {
    const generation = sessionGeneration;
    let rotated = false;
    const pending = refreshSession()
      .then(async (session) => {
        assertCurrentSession(generation);
        setAccessToken(session.accessToken);
        rotated = true;
        // Do not recurse into this refresh flight if the renewed token is rejected.
        const bootstrap = await readBootstrap(false);
        assertCurrentSession(generation);
        if (
          bootstrap.user.userId !== session.user.userId ||
          bootstrap.currentUser.userId !== session.user.userId
        ) {
          throw new ApiError(401, "session_identity_mismatch", "Soha session identity changed");
        }
        sessionListener?.(session, bootstrap);
        return session;
      })
      .catch((error) => {
        assertCurrentSession(generation);
        if (
          error instanceof ApiError &&
          (error.status === 401 || error.status === 403)
        ) {
          setAccessToken(null);
          sessionListener?.(null);
          return null;
        }
        // A rotated token without a current authority snapshot must not leave stale permissions installed.
        if (rotated) {
          setAccessToken(null);
          sessionListener?.(null);
        }
        throw error;
      })
      .finally(() => {
        if (refreshInFlight === pending) refreshInFlight = null;
      });
    refreshInFlight = pending;
  }
  return refreshInFlight;
}

async function refreshSession(): Promise<Session> {
  const payload = await request(
    "/auth/refresh",
    { method: "POST", body: "{}" },
    false,
    false,
  );
  return parseAuthSession(payload);
}

async function readPayload(response: Response): Promise<unknown> {
  const generation = responseGenerations.get(response) ?? sessionGeneration;
  assertCurrentSession(generation);
  if (response.status === 204) return null;
  const text = await response.text();
  assertCurrentSession(generation);
  if (!text) return null;
  try {
    return JSON.parse(text) as unknown;
  } catch {
    throw new ApiError(
      response.status,
      "response_contract_mismatch",
      "Invalid Soha server response",
      response.headers.get("X-Request-ID") || undefined,
    );
  }
}

function responseError(response: Response, payload: unknown): ApiError {
  const requestId = response.headers.get("X-Request-ID") || undefined;
  if (isRecord(payload) && isRecord(payload.error)) {
    const code = optionalString(payload.error.code) || "request_failed";
    const message =
      optionalString(payload.error.message) || "Soha request failed";
    return new ApiError(response.status, code, message, requestId);
  }
  return new ApiError(
    response.status,
    "request_failed",
    `Soha request failed (${response.status})`,
    requestId,
  );
}

function parseAuthSession(payload: unknown): Session {
  return parseAuthSessionData(envelopeData(payload));
}

function parseAuthSessionData(data: unknown): Session {
  if (!isRecord(data) || !isPrincipal(data.user) || !isRecord(data.tokens))
    throw contractError();
  if (typeof data.tokens.accessToken !== "string" || !data.tokens.accessToken)
    throw contractError();
  return {
    accessToken: data.tokens.accessToken,
    user: normalizePrincipal(data.user),
  };
}

function getProfileFromData(data: Record<string, unknown>): UserProfile {
  return {
    userId: data.userId as string,
    username: data.username as string,
    displayName: data.displayName as string,
    email: data.email as string,
    phone: optionalString(data.phone),
    avatarUrl: optionalString(data.avatarUrl),
    avatarFit: optionalString(data.avatarFit),
    status: data.status as string,
    roles: stringArray(data.roles),
    teams: stringArray(data.teams),
    projects: stringArray(data.projects),
    tags: stringArray(data.tags),
    identities: Array.isArray(data.identities)
      ? data.identities
          .filter(isRecord)
          .map(normalizeIdentity)
          .filter((item): item is LinkedIdentity => item !== null)
      : [],
    lastLoginAt: optionalString(data.lastLoginAt),
  };
}

function normalizeIdentity(
  value: Record<string, unknown>,
): LinkedIdentity | null {
  if (typeof value.providerType !== "string") return null;
  return {
    id: optionalString(value.id),
    providerType: value.providerType,
    providerId: optionalString(value.providerId),
    displayName: optionalString(value.displayName),
    email: optionalString(value.email),
    lastLoginAt: optionalString(value.lastLoginAt),
  };
}

function envelopeData(payload: unknown): unknown {
  if (!isRecord(payload) || !("data" in payload)) throw contractError();
  return payload.data;
}

function isAuthProvider(value: unknown): value is AuthProvider {
  return (
    isRecord(value) &&
    typeof value.type === "string" &&
    typeof value.name === "string" &&
    typeof value.enabled === "boolean"
  );
}

function isPrincipal(value: unknown): value is Record<string, unknown> {
  return isRecord(value) && hasStrings(value, ["userId", "userName", "email"]);
}

function normalizePrincipal(value: Record<string, unknown>): Principal {
  return {
    ...value,
    userId: value.userId as string,
    userName: value.userName as string,
    email: value.email as string,
    roles: stringArray(value.roles),
    teams: stringArray(value.teams),
    projects: stringArray(value.projects),
    tags: stringArray(value.tags),
    permissionKeys: stringArray(value.permissionKeys),
  };
}

function isAnnouncement(value: unknown): boolean {
  return (
    isRecord(value) &&
    hasStrings(value, ["id", "title", "summary", "level"]) &&
    typeof value.isRead === "boolean"
  );
}

function isNetworkConnectionOption(
  value: unknown,
): value is NetworkConnectionOption {
  if (
    !isRecord(value) ||
    !hasStrings(value, [
      "siteId",
      "siteName",
      "accessMedium",
      "authentication",
      "accessProfile",
    ]) ||
    typeof value.policyVersion !== "number" ||
    value.policyVersion < 1 ||
    !["wifi", "wired"].includes(value.accessMedium as string) ||
    value.authentication !== "radius_802_1x" ||
    !["onboarding", "full", "restricted", "quarantine", "deny"].includes(
      value.accessProfile as string,
    )
  )
    return false;
  return value.accessMedium === "wired"
    ? value.ssid === undefined
    : typeof value.ssid === "string" && value.ssid.length > 0;
}

function isIdentityApplication(
  value: unknown,
): value is Record<string, unknown> {
  return (
    isRecord(value) &&
    hasStrings(value, [
      "id",
      "name",
      "slug",
      "status",
      "createdAt",
      "updatedAt",
    ]) &&
    (!("tags" in value) ||
      (Array.isArray(value.tags) &&
        value.tags.every((item) => typeof item === "string")))
  );
}

function isIdentityApplicationLaunch(
  value: unknown,
): value is Record<string, unknown> {
  return (
    isRecord(value) &&
    hasStrings(value, [
      "id",
      "applicationId",
      "userId",
      "providerType",
      "result",
      "createdAt",
    ])
  );
}

function isPortalBootstrap(value: unknown): value is Record<string, unknown> {
  if (
    !isRecord(value) ||
    !isPrincipal(value.principal) ||
    !isRecord(value.security)
  )
    return false;
  const security = value.security;
  return (
    Array.isArray(value.applications) &&
    value.applications.every(isIdentityApplication) &&
    Array.isArray(value.favorites) &&
    value.favorites.every(isIdentityApplication) &&
    Array.isArray(value.recent) &&
    value.recent.every(isIdentityApplicationLaunch) &&
    Array.isArray(value.categories) &&
    value.categories.every((item) => typeof item === "string") &&
    isPrincipal(security.principal) &&
    typeof security.mfaEnabled === "boolean" &&
    Array.isArray(security.linkedSources) &&
    security.linkedSources.every((item) => typeof item === "string") &&
    typeof security.activeSession === "number"
  );
}

function isPortalLaunchDecision(
  value: unknown,
): value is Record<string, unknown> {
  return (
    isRecord(value) &&
    isIdentityApplication(value.application) &&
    typeof value.launchUrl === "string" &&
    value.launchUrl.length > 0 &&
    typeof value.providerType === "string" &&
    value.decision === "allow" &&
    (!("handoffExpiresAt" in value) ||
      typeof value.handoffExpiresAt === "string")
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hasStrings(value: Record<string, unknown>, keys: string[]): boolean {
  return keys.every((key) => typeof value[key] === "string");
}

function stringArray(value: unknown): string[] {
  return Array.isArray(value)
    ? value.filter((item): item is string => typeof item === "string")
    : [];
}

function optionalString(value: unknown): string | undefined {
  return typeof value === "string" ? value : undefined;
}

function contractError(): ApiError {
  return new ApiError(
    0,
    "response_contract_mismatch",
    "Invalid Soha server response",
  );
}

export async function getVPNConnectionOptions(
  deviceId: string,
): Promise<NetworkVPNConnectionOption[]> {
  const payload = await request(
    `/network-access/vpn/connection-options?deviceId=${encodeURIComponent(deviceId)}`,
  );
  if (
    !isRecord(payload) ||
    !Array.isArray(payload.items) ||
    payload.items.length > 100 ||
    !payload.items.every(
      (item) =>
        isRecord(item) &&
        hasStrings(item, ["profileId", "name", "mode", "selectionStrategy"]) &&
        Array.isArray(item.candidates) &&
        item.candidates.length <= 32,
    )
  )
    throw contractError();
  return payload.items as NetworkVPNConnectionOption[];
}
export async function createVPNIntent(
  input: NetworkVPNConnectionIntentInput,
): Promise<NetworkVPNConnectionIntentSecret> {
  const data = envelopeData(
    await request("/network-access/vpn/connection-intents", {
      method: "POST",
      body: JSON.stringify(input),
    }),
  );
  if (!isRecord(data) || !hasStrings(data, ["intentId", "token", "expiresAt"]))
    throw contractError();
  return data as unknown as NetworkVPNConnectionIntentSecret;
}
export async function getVPNCurrentConnection(
  deviceId: string,
): Promise<NetworkVPNConnectionView | null> {
  const data = envelopeData(
    await request(
      `/network-access/vpn/current-connection?deviceId=${encodeURIComponent(deviceId)}`,
    ),
  );
  if (data === null) return null;
  if (
    !isRecord(data) ||
    !hasStrings(data, ["sessionId", "profileId", "gatewayId", "state"])
  )
    throw contractError();
  return data as unknown as NetworkVPNConnectionView;
}
