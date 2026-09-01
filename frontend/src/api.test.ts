import { afterEach, describe, expect, it, vi } from 'vitest'
import {
  getBootstrap,
  getPortalApplication,
  getPortalBootstrap,
  launchPortalApplication,
  loginWithProvider,
  setAccessToken,
  setPortalFavorite,
  setSessionListener,
} from '@/api'
import { getHostState, openBrowserURL } from '@/native/host'

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
  afterEach(() => {
    setAccessToken(null)
    setSessionListener(null)
    vi.unstubAllGlobals()
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
    expect(JSON.parse(String(init.body))).toEqual({ providerId: 'oidc-main' })
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
        expect(JSON.parse(String(init?.body))).toEqual({ surface: 'desktop' })
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
      expect.objectContaining({
        method: 'POST',
        body: JSON.stringify({
          url: 'https://soha.example.com/auth/browser-handoff/handoff-1',
        }),
      }),
    )
  })
})

function jsonResponse(payload: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { 'Content-Type': 'application/json', ...headers },
  })
}
