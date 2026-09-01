import type {
  Announcement,
  AnnouncementInbox,
  AuthProvider,
  Bootstrap,
  Branding,
  LinkedIdentity,
  LoginOptions,
  Principal,
  ProfileUpdate,
  Session,
  UserProfile,
} from '@/types'
import { startDesktopAuth, wailsRequestBodyHeader } from '@/native/host'

export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
    readonly requestId?: string,
  ) {
    super(message)
    this.name = 'ApiError'
  }
}

let accessToken: string | null = null
let refreshInFlight: Promise<Session | null> | null = null
let sessionListener: ((session: Session | null) => void) | null = null

export function setAccessToken(token: string | null): void {
  accessToken = token
}

export function setSessionListener(listener: ((session: Session | null) => void) | null): void {
  sessionListener = listener
}

export async function loginWithPassword(login: string, password: string): Promise<Session> {
  const payload = await request('/auth/login', {
    method: 'POST',
    body: JSON.stringify({ login, password }),
  }, false, false)
  const session = parseAuthSession(payload)
  setAccessToken(session.accessToken)
  return session
}

export async function loginWithProvider(providerId: string, signal: AbortSignal): Promise<Session> {
  const session = parseAuthSessionData(await startDesktopAuth(providerId, signal))
  setAccessToken(session.accessToken)
  return session
}

export async function restoreSession(): Promise<Session | null> {
  try {
    const session = await refreshSession()
    if (session) setAccessToken(session.accessToken)
    return session
  } catch (error) {
    if (error instanceof ApiError && (error.status === 401 || error.status === 403)) {
      setAccessToken(null)
      return null
    }
    throw error
  }
}

export async function getLoginOptions(): Promise<LoginOptions> {
  const payload = await request('/auth/login-options', {}, false, false)
  const data = envelopeData(payload)
  if (!isRecord(data) || !isRecord(data.verification) || typeof data.verification.sliderEnabled !== 'boolean') {
    throw contractError()
  }
  return data as unknown as LoginOptions
}

export async function getAuthProviders(): Promise<AuthProvider[]> {
  const payload = await request('/auth/providers', {}, false, false)
  if (!isRecord(payload)) throw contractError()
  const providers = Array.isArray(payload.items)
    ? payload.items
    : Array.isArray(payload.data)
      ? payload.data
      : null
  if (!providers) throw contractError()
  return providers.filter(isAuthProvider)
}

export async function getBootstrap(): Promise<Bootstrap> {
  const payload = await request('/auth/bootstrap')
  const data = envelopeData(payload)
  if (!isRecord(data) || !isPrincipal(data.user) || !isPrincipal(data.currentUser)) {
    throw contractError()
  }
  const snapshot = isRecord(data.permissionSnapshot) ? data.permissionSnapshot : {}
  return {
    user: normalizePrincipal(data.user),
    currentUser: normalizePrincipal(data.currentUser),
    permissionSnapshot: { permissionKeys: stringArray(snapshot.permissionKeys) },
    branding: isRecord(data.branding) ? (data.branding as Branding) : {},
  }
}

export async function getProfile(): Promise<UserProfile> {
  const payload = await request('/auth/profile')
  const data = envelopeData(payload)
  if (!isRecord(data) || !hasStrings(data, ['userId', 'username', 'displayName', 'email', 'status'])) {
    throw contractError()
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
      ? data.identities.filter(isRecord).map(normalizeIdentity).filter((item): item is LinkedIdentity => item !== null)
      : [],
    lastLoginAt: optionalString(data.lastLoginAt),
  }
}

export async function updateProfile(input: ProfileUpdate): Promise<UserProfile> {
  const payload = await request('/auth/profile', {
    method: 'PATCH',
    body: JSON.stringify(input),
  })
  const data = envelopeData(payload)
  if (!isRecord(data) || !hasStrings(data, ['userId', 'username', 'displayName', 'email', 'status'])) {
    throw contractError()
  }
  return getProfileFromData(data)
}

export function changePassword(currentPassword: string, newPassword: string): Promise<void> {
  return request('/auth/profile/password', {
    method: 'POST',
    body: JSON.stringify({ currentPassword, newPassword }),
  }).then(() => undefined)
}

export function logoutServer(): Promise<void> {
  return request('/auth/logout', { method: 'POST', body: '{}' }, true, false).then(() => undefined)
}

export async function getAnnouncementInbox(limit = 5): Promise<AnnouncementInbox> {
  const payload = await request(`/announcements/inbox?limit=${limit}`)
  const data = envelopeData(payload)
  if (!isRecord(data) || !Array.isArray(data.items) || typeof data.unreadCount !== 'number') {
    throw contractError()
  }
  return {
    unreadCount: data.unreadCount,
    items: data.items.filter(isAnnouncement).map((item) => item as unknown as Announcement),
  }
}

export function markAnnouncementRead(id: string): Promise<void> {
  return request(`/announcements/${encodeURIComponent(id)}/read`, { method: 'POST', body: '{}' }).then(
    () => undefined,
  )
}

async function request(
  path: string,
  init: RequestInit = {},
  authenticated = true,
  retryAfterRefresh = true,
): Promise<unknown> {
  const headers = new Headers(init.headers)
  headers.set('Accept', 'application/json')
  if (init.body != null && !headers.has('Content-Type')) headers.set('Content-Type', 'application/json')
  if (authenticated && accessToken) headers.set('Authorization', `Bearer ${accessToken}`)
  const wailsBody = typeof init.body === 'string' && isWailsAssetTransport() ? init.body : null
  if (wailsBody !== null) {
    headers.set(wailsRequestBodyHeader, encodeURIComponent(wailsBody))
  }

  let response: Response
  try {
    response = await fetch(`/api/v1${path}`, {
      ...init,
      body: wailsBody === null ? init.body : undefined,
      headers,
      credentials: 'include',
      redirect: 'error',
    })
  } catch {
    throw new ApiError(0, 'network_error', 'Soha server is unavailable')
  }

  if (response.status === 401 && authenticated && retryAfterRefresh) {
    const session = await singleFlightRefresh()
    if (session) return request(path, init, authenticated, false)
  }

  const payload = await readPayload(response)
  if (!response.ok) throw responseError(response, payload)
  return payload
}

function isWailsAssetTransport(): boolean {
  return globalThis.location.protocol === 'wails:' || globalThis.location.hostname === 'wails.localhost'
}

async function singleFlightRefresh(): Promise<Session | null> {
  if (!refreshInFlight) {
    refreshInFlight = refreshSession()
      .then((session) => {
        if (session) {
          setAccessToken(session.accessToken)
          sessionListener?.(session)
        }
        return session
      })
      .catch((error) => {
        if (error instanceof ApiError && (error.status === 401 || error.status === 403)) {
          setAccessToken(null)
          sessionListener?.(null)
          return null
        }
        throw error
      })
      .finally(() => {
        refreshInFlight = null
      })
  }
  return refreshInFlight
}

async function refreshSession(): Promise<Session> {
  const payload = await request('/auth/refresh', { method: 'POST', body: '{}' }, false, false)
  return parseAuthSession(payload)
}

async function readPayload(response: Response): Promise<unknown> {
  if (response.status === 204) return null
  const text = await response.text()
  if (!text) return null
  try {
    return JSON.parse(text) as unknown
  } catch {
    throw new ApiError(
      response.status,
      'response_contract_mismatch',
      'Invalid Soha server response',
      response.headers.get('X-Request-ID') || undefined,
    )
  }
}

function responseError(response: Response, payload: unknown): ApiError {
  const requestId = response.headers.get('X-Request-ID') || undefined
  if (isRecord(payload) && isRecord(payload.error)) {
    const code = optionalString(payload.error.code) || 'request_failed'
    const message = optionalString(payload.error.message) || 'Soha request failed'
    return new ApiError(response.status, code, message, requestId)
  }
  return new ApiError(response.status, 'request_failed', `Soha request failed (${response.status})`, requestId)
}

function parseAuthSession(payload: unknown): Session {
  return parseAuthSessionData(envelopeData(payload))
}

function parseAuthSessionData(data: unknown): Session {
  if (!isRecord(data) || !isPrincipal(data.user) || !isRecord(data.tokens)) throw contractError()
  if (typeof data.tokens.accessToken !== 'string' || !data.tokens.accessToken) throw contractError()
  return { accessToken: data.tokens.accessToken, user: normalizePrincipal(data.user) }
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
      ? data.identities.filter(isRecord).map(normalizeIdentity).filter((item): item is LinkedIdentity => item !== null)
      : [],
    lastLoginAt: optionalString(data.lastLoginAt),
  }
}

function normalizeIdentity(value: Record<string, unknown>): LinkedIdentity | null {
  if (typeof value.providerType !== 'string') return null
  return {
    id: optionalString(value.id),
    providerType: value.providerType,
    providerId: optionalString(value.providerId),
    displayName: optionalString(value.displayName),
    email: optionalString(value.email),
    lastLoginAt: optionalString(value.lastLoginAt),
  }
}

function envelopeData(payload: unknown): unknown {
  if (!isRecord(payload) || !('data' in payload)) throw contractError()
  return payload.data
}

function isAuthProvider(value: unknown): value is AuthProvider {
  return isRecord(value) && typeof value.type === 'string' && typeof value.name === 'string' && typeof value.enabled === 'boolean'
}

function isPrincipal(value: unknown): value is Record<string, unknown> {
  return isRecord(value) && hasStrings(value, ['userId', 'userName', 'email'])
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
  }
}

function isAnnouncement(value: unknown): boolean {
  return isRecord(value) && hasStrings(value, ['id', 'title', 'summary', 'level']) && typeof value.isRead === 'boolean'
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function hasStrings(value: Record<string, unknown>, keys: string[]): boolean {
  return keys.every((key) => typeof value[key] === 'string')
}

function stringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === 'string') : []
}

function optionalString(value: unknown): string | undefined {
  return typeof value === 'string' ? value : undefined
}

function contractError(): ApiError {
  return new ApiError(0, 'response_contract_mismatch', 'Invalid Soha server response')
}
