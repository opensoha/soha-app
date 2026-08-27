import type { ConnectionCheck, HostState } from '@/types'

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

export function startDesktopAuth(providerId: string, signal: AbortSignal): Promise<unknown> {
  return hostRequest<unknown>('/app/v1/auth/desktop/start', {
    ...jsonRequest({ providerId }),
    signal,
  })
}

function jsonRequest(body: object): RequestInit {
  return {
    method: 'POST',
    credentials: 'include',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  }
}

async function hostRequest<T>(path: string, init: RequestInit = {}): Promise<T> {
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
    | null
  if (!response.ok) {
    const error = payload && 'error' in payload ? payload.error : undefined
    throw new HostError(
      response.status,
      error?.code || 'host_request_failed',
      error?.message || 'Soha App host request failed',
      response.headers.get('X-Request-ID') || undefined,
    )
  }
  if (!payload || !('data' in payload)) {
    throw new HostError(
      response.status,
      'host_contract_mismatch',
      'Invalid Soha App host response',
      response.headers.get('X-Request-ID') || undefined,
    )
  }
  return payload.data
}
