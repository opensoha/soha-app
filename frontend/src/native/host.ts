import type {
  ConnectionCheck,
  HostState,
  SoftwareListResponse,
  SoftwareTaskResponse,
} from '@/types'

interface DataEnvelope<T> {
  data: T
}

interface ErrorEnvelope {
  error?: { code?: string; message?: string }
}

interface PreparedSwitch {
  activationToken: string
  connection: ConnectionCheck
}

export const wailsRequestBodyHeader = 'X-Soha-App-Body'

export interface UpdateCheckResult {
  message: string
}

export class HostError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
    readonly requestId?: string,
  ) {
    super(message)
    this.name = 'HostError'
  }
}

export function getHostState(): Promise<HostState> {
  return hostRequest<HostState>('/app/v1/state')
}

export function checkServer(serverUrl: string): Promise<ConnectionCheck> {
  return hostRequest<ConnectionCheck>('/app/v1/connections/check', jsonRequest({ serverUrl }))
}

export async function prepareServerSwitch(
  serverUrl: string,
  accessToken?: string,
): Promise<PreparedSwitch> {
  const request = jsonRequest({ serverUrl })
  if (accessToken) request.headers = { ...request.headers, Authorization: `Bearer ${accessToken}` }
  return hostRequest<PreparedSwitch>('/app/v1/connections/switch', request)
}

export function activateServerSwitch(activationToken: string): Promise<HostState> {
  return hostRequest<HostState>(
    '/app/v1/connections/activate',
    jsonRequest({ activationToken }),
  )
}

export function clearHostSession(): Promise<void> {
  return hostRequest('/app/v1/session/clear', jsonRequest({})).then(() => undefined)
}

export function openLogDirectory(): Promise<void> {
  return hostRequest('/app/v1/logs/open', jsonRequest({})).then(() => undefined)
}

export function checkForUpdates(): Promise<UpdateCheckResult> {
  return hostRequest<UpdateCheckResult>(
    '/app/v1/updates/check',
    jsonRequest({}),
    false,
  )
}

export function listSoftware(accessToken: string): Promise<SoftwareListResponse> {
  return hostRequest<SoftwareListResponse>(
    '/app/v1/software',
    bearerRequest(accessToken),
    false,
  )
}

export function installSoftware(
  softwareId: string,
  accessToken: string,
): Promise<SoftwareTaskResponse> {
  return hostRequest<SoftwareTaskResponse>(
    `/app/v1/software/${encodeURIComponent(softwareId)}/install`,
    bearerRequest(accessToken, jsonRequest({})),
    false,
  )
}

export function getSoftwareTask(taskId: string): Promise<SoftwareTaskResponse> {
  return hostRequest<SoftwareTaskResponse>(
    `/app/v1/software/tasks/${encodeURIComponent(taskId)}`,
    {},
    false,
  )
}

export function openBrowserURL(url: string): Promise<void> {
  return hostRequest('/app/v1/browser/open', jsonRequest({ url })).then(() => undefined)
}

export function startDesktopAuth(providerId: string, signal: AbortSignal): Promise<unknown> {
  return hostRequest<unknown>('/app/v1/auth/desktop/start', {
    ...jsonRequest({ providerId }),
    signal,
  })
}

function jsonRequest(body: object): RequestInit {
  const payload = JSON.stringify(body)
  return {
    method: 'POST',
    credentials: 'include',
    headers: {
      'Content-Type': 'application/json',
      [wailsRequestBodyHeader]: encodeURIComponent(payload),
    },
  }
}

function bearerRequest(accessToken: string, init: RequestInit = {}): RequestInit {
  return {
    ...init,
    headers: { ...init.headers, Authorization: `Bearer ${accessToken}` },
  }
}

async function hostRequest<T>(
  path: string,
  init: RequestInit = {},
  expectsDataEnvelope = true,
): Promise<T> {
  let response: Response
  try {
    response = await fetch(path, { credentials: 'include', ...init })
  } catch (error) {
    if (init.signal?.aborted) throw error
    throw new HostError(0, 'host_unavailable', 'Soha App host is unavailable')
  }

  const payload = (await response.json().catch(() => null)) as
    | DataEnvelope<T>
    | ErrorEnvelope
    | T
    | null
  const envelope = payload as (DataEnvelope<T> & ErrorEnvelope) | null
  if (!response.ok) {
    const error = envelope?.error
    throw new HostError(
      response.status,
      error?.code || 'host_request_failed',
      error?.message || 'Soha App host request failed',
      response.headers.get('X-Request-ID') || undefined,
    )
  }
  if (!payload || typeof payload !== 'object' || (expectsDataEnvelope && !('data' in payload))) {
    throw new HostError(
      response.status,
      'host_contract_mismatch',
      'Invalid Soha App host response',
      response.headers.get('X-Request-ID') || undefined,
    )
  }
  return expectsDataEnvelope ? envelope!.data : payload as T
}
