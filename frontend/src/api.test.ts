import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import {
  changePassword,
  getBootstrap,
  loginWithProvider,
  loginWithPassword,
  logoutServer,
  setAccessToken,
  setSessionListener,
  updateProfile,
} from '@/api'
import {
  checkForUpdates,
  getHostState,
  getSoftwareTask,
  installSoftware,
  listSoftware,
  wailsRequestBodyHeader,
} from '@/native/host'

const principal = {
  userId: 'user-1',
  userName: 'admin',
  email: 'admin@soha.local',
  roles: [],
  teams: [],
  projects: [],
  tags: [],
}

describe('API transport', () => {
  beforeEach(() => {
    vi.stubGlobal('location', new URL('wails://localhost'))
  })

  afterEach(() => {
    setAccessToken(null)
    setSessionListener(null)
    vi.unstubAllGlobals()
  })

  it('sends password login JSON through the Wails body header', async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse({
      data: {
        user: principal,
        tokens: {
          accessToken: 'password-access',
          refreshToken: 'http-only-refresh',
          tokenType: 'Bearer',
          expiresIn: 300,
          expiresAt: '2026-08-20T00:00:00Z',
        },
      },
    }))
    vi.stubGlobal('fetch', fetchMock)

    await expect(loginWithPassword('opensoha', 'secret-password')).resolves.toMatchObject({
      accessToken: 'password-access',
    })

    const [path, init] = fetchMock.mock.calls[0] as [string, RequestInit]
    expect(path).toBe('/api/v1/auth/login')
    expect(decodedRequestBody(init)).toBe('{"login":"opensoha","password":"secret-password"}')
    expect(new Headers(init.headers).get('Content-Type')).toBe('application/json')
  })

  it('keeps password login JSON in the standard HTTP request body', async () => {
    vi.stubGlobal('location', new URL('http://127.0.0.1:9245'))
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse({
      data: {
        user: principal,
        tokens: {
          accessToken: 'password-access',
          refreshToken: 'http-only-refresh',
          tokenType: 'Bearer',
          expiresIn: 300,
          expiresAt: '2026-08-20T00:00:00Z',
        },
      },
    }))
    vi.stubGlobal('fetch', fetchMock)

    await loginWithPassword('opensoha', 'secret-password')

    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit]
    expect(init.body).toBe('{"login":"opensoha","password":"secret-password"}')
    expect(new Headers(init.headers).get(wailsRequestBodyHeader)).toBeNull()
  })

  it('uses one refresh for concurrent 401 responses and retries each request once', async () => {
    let refreshCalls = 0
    let resolveRefresh: ((response: Response) => void) | undefined
    const authorizations: string[] = []
    const fetchMock = vi.fn((input: string | URL | Request, init?: RequestInit) => {
      const path = String(input)
      const headers = new Headers(init?.headers)
      if (path.endsWith('/auth/refresh')) {
        refreshCalls += 1
        return new Promise<Response>((resolve) => {
          resolveRefresh = resolve
        })
      }
      if (path.endsWith('/auth/bootstrap')) {
        const authorization = headers.get('Authorization') || ''
        authorizations.push(authorization)
        if (authorization === 'Bearer old-token') {
          return Promise.resolve(jsonResponse({ error: { code: 'unauthorized', message: 'Unauthorized' } }, 401))
        }
        return Promise.resolve(jsonResponse({
          data: {
            user: principal,
            currentUser: principal,
            permissionSnapshot: { permissionKeys: [] },
            branding: {},
          },
        }))
      }
      throw new Error(`unexpected request: ${path}`)
    })
    vi.stubGlobal('fetch', fetchMock)
    setAccessToken('old-token')

    const first = getBootstrap()
    const second = getBootstrap()
    await vi.waitFor(() => expect(refreshCalls).toBe(1))
    resolveRefresh?.(jsonResponse({
      data: {
        user: principal,
        tokens: {
          accessToken: 'new-token',
          refreshToken: 'must-not-escape',
          tokenType: 'Bearer',
          expiresIn: 300,
          expiresAt: '2026-08-20T00:00:00Z',
        },
      },
    }))

    await Promise.all([first, second])
    expect(refreshCalls).toBe(1)
    expect(authorizations).toEqual([
      'Bearer old-token',
      'Bearer old-token',
      'Bearer new-token',
      'Bearer new-token',
    ])
  })

  it.each([401, 403])('clears the session after refresh status %i without retrying in a loop', async (refreshStatus) => {
    const listener = vi.fn()
    setSessionListener(listener)
    setAccessToken('expired-token')
    let bootstrapCalls = 0
    let refreshCalls = 0
    vi.stubGlobal('fetch', vi.fn((input: string | URL | Request) => {
      const path = String(input)
      if (path.endsWith('/auth/bootstrap')) {
        bootstrapCalls += 1
        return Promise.resolve(jsonResponse({ error: { code: 'unauthorized', message: 'Unauthorized' } }, 401))
      }
      if (path.endsWith('/auth/refresh')) {
        refreshCalls += 1
        return Promise.resolve(jsonResponse({ error: { code: 'refresh_expired', message: 'Expired' } }, refreshStatus))
      }
      throw new Error(`unexpected request: ${path}`)
    }))

    await expect(getBootstrap()).rejects.toMatchObject({ status: 401, code: 'unauthorized' })

    expect(bootstrapCalls).toBe(1)
    expect(refreshCalls).toBe(1)
    expect(listener).toHaveBeenCalledOnce()
    expect(listener).toHaveBeenCalledWith(null)
  })

  it('keeps the access token when refresh fails because the Server is unreachable', async () => {
    const listener = vi.fn()
    const authorizations: string[] = []
    let bootstrapCalls = 0
    setSessionListener(listener)
    setAccessToken('offline-token')
    vi.stubGlobal('fetch', vi.fn((input: string | URL | Request, init?: RequestInit) => {
      const path = String(input)
      if (path.endsWith('/auth/refresh')) return Promise.reject(new Error('offline'))
      if (path.endsWith('/auth/bootstrap')) {
        bootstrapCalls += 1
        authorizations.push(new Headers(init?.headers).get('Authorization') || '')
        if (bootstrapCalls === 1) {
          return Promise.resolve(jsonResponse({ error: { code: 'unauthorized', message: 'Unauthorized' } }, 401))
        }
        return Promise.resolve(jsonResponse({
          data: {
            user: principal,
            currentUser: principal,
            permissionSnapshot: { permissionKeys: [] },
            branding: {},
          },
        }))
      }
      throw new Error(`unexpected request: ${path}`)
    }))

    await expect(getBootstrap()).rejects.toMatchObject({ status: 0, code: 'network_error' })
    await expect(getBootstrap()).resolves.toMatchObject({ user: principal })

    expect(listener).not.toHaveBeenCalled()
    expect(authorizations).toEqual(['Bearer offline-token', 'Bearer offline-token'])
  })

  it('preserves the response request ID on API errors', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(jsonResponse(
      { error: { code: 'upstream_unavailable', message: 'Try again later' } },
      503,
      { 'X-Request-ID': 'request-503' },
    )))

    await expect(getBootstrap()).rejects.toMatchObject({
      status: 503,
      code: 'upstream_unavailable',
      requestId: 'request-503',
    })
  })

  it('preserves the response request ID on host errors', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(jsonResponse(
      { error: { code: 'configuration_unavailable', message: 'Configuration is unavailable' } },
      503,
      { 'X-Request-ID': 'host-request-503' },
    )))

    await expect(getHostState()).rejects.toMatchObject({
      status: 503,
      code: 'configuration_unavailable',
      requestId: 'host-request-503',
    })
  })

  it('uses the authenticated profile, password, and logout contracts', async () => {
    const profile = {
      userId: 'user-1',
      username: 'admin',
      displayName: 'Soha Admin',
      email: 'admin@soha.local',
      phone: '13800138000',
      avatarUrl: 'https://soha.local/avatar.png',
      avatarFit: 'cover',
      status: 'active',
      roles: ['admin'],
      teams: [],
      projects: [],
      tags: [],
      identities: [],
    }
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(jsonResponse({ data: profile }))
      .mockResolvedValueOnce(jsonResponse({ data: { message: 'password changed' } }))
      .mockResolvedValueOnce(new Response(null, { status: 204 }))
    vi.stubGlobal('fetch', fetchMock)
    setAccessToken('profile-token')

    await expect(updateProfile({
      displayName: profile.displayName,
      email: profile.email,
      phone: profile.phone,
      avatarUrl: profile.avatarUrl,
      avatarFit: profile.avatarFit,
    })).resolves.toEqual(profile)
    await expect(changePassword('old-password', 'new-password')).resolves.toBeUndefined()
    await expect(logoutServer()).resolves.toBeUndefined()

    const [profilePath, profileInit] = fetchMock.mock.calls[0] as [string, RequestInit]
    expect(profilePath).toBe('/api/v1/auth/profile')
    expect(profileInit).toMatchObject({
      method: 'PATCH',
      credentials: 'include',
    })
    expect(decodedRequestBody(profileInit)).toBe(JSON.stringify({
      displayName: profile.displayName,
      email: profile.email,
      phone: profile.phone,
      avatarUrl: profile.avatarUrl,
      avatarFit: profile.avatarFit,
    }))

    const [passwordPath, passwordInit] = fetchMock.mock.calls[1] as [string, RequestInit]
    expect(passwordPath).toBe('/api/v1/auth/profile/password')
    expect(passwordInit).toMatchObject({
      method: 'POST',
      credentials: 'include',
    })
    expect(decodedRequestBody(passwordInit)).toBe(JSON.stringify({
      currentPassword: 'old-password',
      newPassword: 'new-password',
    }))

    const [logoutPath, logoutInit] = fetchMock.mock.calls[2] as [string, RequestInit]
    expect(logoutPath).toBe('/api/v1/auth/logout')
    expect(logoutInit).toMatchObject({ method: 'POST', credentials: 'include' })
    expect(decodedRequestBody(logoutInit)).toBe('{}')

    for (const init of [profileInit, passwordInit, logoutInit]) {
      expect(new Headers(init.headers).get('Authorization')).toBe('Bearer profile-token')
    }
  })

  it('checks for desktop updates through the runtime endpoint', async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse({ message: '更新检查已完成' }))
    vi.stubGlobal('fetch', fetchMock)

    await expect(checkForUpdates()).resolves.toEqual({ message: '更新检查已完成' })

    expect(fetchMock).toHaveBeenCalledOnce()
    expect(fetchMock).toHaveBeenCalledWith('/app/v1/updates/check', expect.objectContaining({
      credentials: 'include',
      method: 'POST',
    }))
    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit]
    expect(decodedRequestBody(init)).toBe('{}')
  })

  it('preserves runtime update errors and request IDs', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(jsonResponse(
      { error: { code: 'updates_unavailable', message: '当前构建未配置更新源' } },
      503,
      { 'X-Request-ID': 'update-request-503' },
    )))

    await expect(checkForUpdates()).rejects.toMatchObject({
      status: 503,
      code: 'updates_unavailable',
      message: '当前构建未配置更新源',
      requestId: 'update-request-503',
    })
  })

  it('uses the native software endpoints without exposing raw artifact metadata', async () => {
    const software = {
      id: 'package/desktop agent',
      name: 'Soha Agent',
      publisher: 'OpenSoha',
      version: '1.2.3',
      size: 12_345,
    }
    const queued = {
      id: 'task/1',
      softwareId: software.id,
      name: software.name,
      state: 'queued' as const,
      progress: 0,
      message: '等待下载',
    }
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(jsonResponse({ items: [software] }))
      .mockResolvedValueOnce(jsonResponse({ task: queued }, 202))
      .mockResolvedValueOnce(jsonResponse({ task: { ...queued, state: 'completed', progress: 100 } }))
    vi.stubGlobal('fetch', fetchMock)

    const listed = await listSoftware('access-token')
    expect(listed).toEqual({ items: [software] })
    expect(listed.items[0]).not.toHaveProperty('sha256')
    await expect(installSoftware(software.id, 'access-token')).resolves.toEqual({ task: queued })
    await expect(getSoftwareTask(queued.id)).resolves.toMatchObject({ task: { state: 'completed' } })

    const [listPath, listInit] = fetchMock.mock.calls[0] as [string, RequestInit]
    expect(listPath).toBe('/app/v1/software')
    expect(new Headers(listInit.headers).get('Authorization')).toBe('Bearer access-token')

    const [installPath, installInit] = fetchMock.mock.calls[1] as [string, RequestInit]
    expect(installPath).toBe('/app/v1/software/package%2Fdesktop%20agent/install')
    expect(installInit.method).toBe('POST')
    expect(new Headers(installInit.headers).get('Authorization')).toBe('Bearer access-token')

    const [taskPath, taskInit] = fetchMock.mock.calls[2] as [string, RequestInit]
    expect(taskPath).toBe('/app/v1/software/tasks/task%2F1')
    expect(new Headers(taskInit.headers).get('Authorization')).toBeNull()
  })

  it('starts desktop provider login through the host and keeps only the access token', async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse({
      data: {
        user: principal,
        tokens: {
          accessToken: 'desktop-access',
          refreshToken: 'http-only-refresh',
          tokenType: 'Bearer',
          expiresIn: 300,
          expiresAt: '2026-08-20T00:00:00Z',
        },
      },
    }))
    vi.stubGlobal('fetch', fetchMock)
    const controller = new AbortController()

    const session = await loginWithProvider('oidc-main', controller.signal)

    expect(session).toEqual({ accessToken: 'desktop-access', user: { ...principal, permissionKeys: [] } })
    expect(fetchMock).toHaveBeenCalledOnce()
    const [path, init] = fetchMock.mock.calls[0] as [string, RequestInit]
    expect(path).toBe('/app/v1/auth/desktop/start')
    expect(JSON.parse(decodedRequestBody(init))).toEqual({ providerId: 'oidc-main' })
    expect(init.signal).toBe(controller.signal)
  })
})

function decodedRequestBody(init: RequestInit): string {
  expect(init.body).toBeUndefined()
  const encodedBody = new Headers(init.headers).get(wailsRequestBodyHeader)
  expect(encodedBody).not.toBeNull()
  return decodeURIComponent(encodedBody!)
}

function jsonResponse(payload: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { 'Content-Type': 'application/json', ...headers },
  })
}
