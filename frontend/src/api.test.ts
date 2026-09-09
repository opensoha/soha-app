import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import {
  changePassword,
  createNetworkAccessGrant,
  getBootstrap,
  getNetworkConnectionOptions,
  getPortalApplication,
  getPortalBootstrap,
  launchPortalApplication,
  loginWithProvider,
  loginWithPassword,
  logoutServer,
  registerEndpointDevice,
  setAccessToken,
  setPortalFavorite,
  setSessionListener,
  updateProfile,
} from '@/api'
import {
  checkForUpdates,
  connectNetwork,
  disconnectNetwork,
  getUpdateStatus,
  getHostState,
  getNetworkStatus,
  getSoftwareTask,
  installSoftware,
  installUpdate,
  listSoftware,
  openBrowserURL,
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

  it('registers the local endpoint with the authenticated session', async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse({ data: {} }))
    vi.stubGlobal('fetch', fetchMock)
    setAccessToken('device-access')

    await registerEndpointDevice('endpoint-mac-1', {
      name: 'MacBook Pro',
      hostname: 'macbook.local',
      platform: 'darwin',
      deviceType: 'laptop',
      reportedFacts: {
        osName: 'macOS',
        osVersion: '15.6.1',
        architecture: 'arm64',
        agentVersion: '0.2.0',
        collectedAt: '2026-09-03T09:00:00Z',
        networkInterfaces: [],
      },
    })

    const [path, init] = fetchMock.mock.calls[0] as [string, RequestInit]
    expect(path).toBe('/api/v1/network-access/devices/endpoint-mac-1/registration')
    expect(init.method).toBe('PUT')
    expect(new Headers(init.headers).get('Authorization')).toBe('Bearer device-access')
    expect(JSON.parse(decodedRequestBody(init))).toEqual({
      name: 'MacBook Pro',
      hostname: 'macbook.local',
      platform: 'darwin',
      deviceType: 'laptop',
      reportedFacts: {
        osName: 'macOS',
        osVersion: '15.6.1',
        architecture: 'arm64',
        agentVersion: '0.2.0',
        collectedAt: '2026-09-03T09:00:00Z',
        networkInterfaces: [],
      },
    })
  })

  it('loads only typed Wi-Fi and wired connection options for the local endpoint', async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse({
      items: [
        {
          siteId: 'site-1',
          siteName: 'Shanghai HQ',
          accessMedium: 'wifi',
          ssid: 'Soha-Staff',
          authentication: 'radius_802_1x',
          accessProfile: 'full',
          policyVersion: 7,
        },
        {
          siteId: 'site-1',
          siteName: 'Shanghai HQ',
          accessMedium: 'wired',
          authentication: 'radius_802_1x',
          accessProfile: 'restricted',
          policyVersion: 7,
        },
      ],
    }))
    vi.stubGlobal('fetch', fetchMock)
    setAccessToken('device-access')

    await expect(getNetworkConnectionOptions('endpoint-mac-1')).resolves.toHaveLength(2)
    const [path, init] = fetchMock.mock.calls[0] as [string, RequestInit]
    expect(path).toBe('/api/v1/network-access/connection-options?deviceId=endpoint-mac-1')
    expect(new Headers(init.headers).get('Authorization')).toBe('Bearer device-access')
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

  it('uses direct host contracts for network status and actions', async () => {
    const disconnected = {
      state: 'disconnected' as const,
      runtimeId: 'endpoint-1',
      deviceId: 'device-1',
      configurationVersion: 0,
      policyVersion: 0,
      uptimeSeconds: 10,
    }
    const connected = {
      ...disconnected,
      state: 'connected' as const,
      siteId: 'site-1',
      networkSpaceId: 'space-1',
      sessionId: 'session-1',
    }
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(jsonResponse(disconnected))
      .mockResolvedValueOnce(jsonResponse(connected))
      .mockResolvedValueOnce(jsonResponse(disconnected))
    vi.stubGlobal('fetch', fetchMock)

    await expect(getNetworkStatus()).resolves.toEqual(disconnected)
		await expect(connectNetwork({ siteId: 'site-1', networkSpaceId: 'space-1', gatewayId: 'gateway-b', mode: 'internal_ztna', resourceIds: ['resource-db'], accessGrantId: 'grant-1', accessGrantToken: 'grant-token' })).resolves.toEqual(connected)
    await expect(disconnectNetwork()).resolves.toEqual(disconnected)

    expect(fetchMock.mock.calls[0]?.[0]).toBe('/app/v1/network/status')
    expect(fetchMock.mock.calls[1]?.[0]).toBe('/app/v1/network/connect')
    expect(decodedRequestBody(fetchMock.mock.calls[1]?.[1] as RequestInit))
			.toBe('{"siteId":"site-1","networkSpaceId":"space-1","gatewayId":"gateway-b","mode":"internal_ztna","resourceIds":["resource-db"],"accessGrantId":"grant-1","accessGrantToken":"grant-token"}')
    expect(fetchMock.mock.calls[2]?.[0]).toBe('/app/v1/network/disconnect')
    expect(decodedRequestBody(fetchMock.mock.calls[2]?.[1] as RequestInit)).toBe('{}')
  })

  it('creates a short-lived network access grant through the authenticated management API', async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse({
      data: {
        grant: {
          id: 'grant-1',
          subjectId: 'user-1',
          deviceId: 'device-1',
          siteId: 'site-1',
          networkSpaceId: 'space-1',
          mode: 'internal_ztna',
          resourceIds: ['resource-db'],
          policyVersion: 7,
          status: 'issued',
          createdBy: 'user-1',
          createdAt: '2026-09-03T00:00:00Z',
          expiresAt: '2026-09-03T00:05:00Z',
        },
        token: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      },
    }))
    vi.stubGlobal('fetch', fetchMock)
    setAccessToken('access-token')

    await expect(createNetworkAccessGrant({
      deviceId: 'device-1',
      siteId: 'site-1',
      networkSpaceId: 'space-1',
      mode: 'internal_ztna',
      resourceIds: ['resource-db'],
      ttlSeconds: 300,
    })).resolves.toMatchObject({ token: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', grant: { id: 'grant-1' } })

    const [path, init] = fetchMock.mock.calls[0] as [string, RequestInit]
    expect(path).toBe('/api/v1/network-access/access-grants')
    expect(new Headers(init.headers).get('Authorization')).toBe('Bearer access-token')
    expect(decodedRequestBody(init)).toBe('{"deviceId":"device-1","siteId":"site-1","networkSpaceId":"space-1","mode":"internal_ztna","resourceIds":["resource-db"],"ttlSeconds":300}')
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

  it('reads, checks, and explicitly installs desktop updates through separate runtime endpoints', async () => {
    const status = {
      supported: true,
      installMode: 'self' as const,
      state: 'available',
      currentVersion: '0.2.0',
      availableVersion: '0.2.1',
      downloadMode: 'delta' as const,
    }
    const fetchMock = vi.fn().mockImplementation(() => Promise.resolve(jsonResponse(status)))
    vi.stubGlobal('fetch', fetchMock)

    await expect(getUpdateStatus()).resolves.toEqual(status)
    await expect(checkForUpdates()).resolves.toEqual(status)
    await expect(installUpdate()).resolves.toEqual(status)

    expect(fetchMock).toHaveBeenCalledTimes(3)
    expect(fetchMock).toHaveBeenNthCalledWith(1, '/app/v1/updates/status', expect.objectContaining({
      credentials: 'include',
    }))
    expect(fetchMock).toHaveBeenNthCalledWith(2, '/app/v1/updates/check', expect.objectContaining({
      credentials: 'include',
      method: 'POST',
    }))
    expect(fetchMock).toHaveBeenNthCalledWith(3, '/app/v1/updates/install', expect.objectContaining({
      credentials: 'include',
      method: 'POST',
    }))
    for (const call of fetchMock.mock.calls.slice(1)) {
      const [, init] = call as [string, RequestInit]
      expect(decodedRequestBody(init)).toBe('{}')
    }
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

  it('uses generated portal envelopes, encoded IDs, and the current App bearer', async () => {
    const application = {
      id: 'app/1',
      slug: 'console',
      name: 'Soha Console',
      status: 'enabled',
      createdAt: '2026-08-31T01:00:00Z',
      updatedAt: '2026-08-31T01:00:00Z',
    }
    const bootstrap = {
      principal,
      applications: [application],
      favorites: [],
      recent: [],
      categories: ['console'],
      security: {
        principal,
        mfaEnabled: false,
        linkedSources: [],
        activeSession: 1,
      },
    }
    const fetchMock = vi.fn((input: string | URL | Request, init?: RequestInit) => {
      const path = String(input)
      const method = init?.method || 'GET'
      expect(new Headers(init?.headers).get('Authorization')).toBe('Bearer portal-token')
      if (path.endsWith('/portal/bootstrap')) return Promise.resolve(jsonResponse({ data: bootstrap }))
      if (path.endsWith('/portal/applications/app%2F1') && method === 'GET') {
        return Promise.resolve(jsonResponse({ data: application }))
      }
      if (path.endsWith('/portal/applications/app%2F1/launch')) {
        expect(JSON.parse(decodedRequestBody(init!))).toEqual({ surface: 'desktop' })
        return Promise.resolve(jsonResponse({
          data: {
            application,
            launchUrl: '/auth/browser-handoff/handoff-1',
            providerType: 'link',
            decision: 'allow',
            handoffExpiresAt: '2026-08-31T01:01:00Z',
          },
        }))
      }
      if (path.endsWith('/portal/applications/app%2F1/favorite') && method === 'POST') {
        return Promise.resolve(jsonResponse({ data: { ...application, favorite: true } }))
      }
      if (path.endsWith('/portal/applications/app%2F1/favorite') && method === 'DELETE') {
        return Promise.resolve(new Response(null, { status: 204 }))
      }
      throw new Error(`unexpected request: ${method} ${path}`)
    })
    vi.stubGlobal('fetch', fetchMock)
    setAccessToken('portal-token')

    await expect(getPortalBootstrap()).resolves.toEqual(bootstrap)
    await expect(getPortalApplication('app/1')).resolves.toEqual(application)
    await expect(launchPortalApplication('app/1')).resolves.toMatchObject({
      launchUrl: '/auth/browser-handoff/handoff-1',
      handoffExpiresAt: '2026-08-31T01:01:00Z',
    })
    await expect(setPortalFavorite('app/1', true)).resolves.toMatchObject({ favorite: true })
    await expect(setPortalFavorite('app/1', false)).resolves.toBeUndefined()
  })

  it('opens external navigation only through the App host action', async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse({ data: { status: 'ok' } }))
    vi.stubGlobal('fetch', fetchMock)

    await openBrowserURL('https://soha.example.com/auth/browser-handoff/handoff-1')

    expect(fetchMock).toHaveBeenCalledWith(
      '/app/v1/browser/open',
      expect.objectContaining({ method: 'POST' }),
    )
    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit]
    expect(JSON.parse(decodedRequestBody(init))).toEqual({
      url: 'https://soha.example.com/auth/browser-handoff/handoff-1',
    })
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
