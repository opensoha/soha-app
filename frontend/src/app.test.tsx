import { act } from 'react'
import { createRoot, type Root } from 'react-dom/client'
import { App as AntApp, ConfigProvider } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { DesktopApp } from '@/app'
import {
  ApiError,
  changePassword,
  getAnnouncementInbox,
  getAuthProviders,
  getBootstrap,
  getLoginOptions,
  getProfile,
  loginWithProvider,
  loginWithPassword,
  logoutServer,
  markAnnouncementRead,
  restoreSession,
  setSessionListener,
  updateProfile,
} from '@/api'
import {
  activateServerSwitch,
  checkServer,
  clearHostSession,
  getHostState,
  prepareServerSwitch,
} from '@/native/host'
import { useAppStore } from '@/store'

vi.mock('@/native/host', () => ({
  HostError: class HostError extends Error {
    constructor(
      readonly status: number,
      readonly code: string,
      message: string,
      readonly requestId?: string,
    ) {
      super(message)
    }
  },
  getHostState: vi.fn().mockResolvedValue({
    serverUrl: 'https://soha.example.com',
    configurationSource: 'saved',
    managedByEnvironment: false,
    app: {
      name: 'Soha',
      version: 'test',
      platform: 'darwin',
      arch: 'arm64',
      logDirectory: '/tmp/logs',
      updateSupported: false,
    },
  }),
  checkServer: vi.fn().mockResolvedValue({ status: 'online', serverUrl: 'https://soha.example.com' }),
  clearHostSession: vi.fn().mockResolvedValue(undefined),
  prepareServerSwitch: vi.fn(),
  activateServerSwitch: vi.fn(),
  openLogDirectory: vi.fn(),
}))

vi.mock('@/api', () => {
  const user = {
    userId: 'user-1',
    userName: 'admin',
    email: 'admin@soha.local',
    roles: [],
    teams: [],
    projects: [],
    tags: [],
  }
  return {
    ApiError: class ApiError extends Error {
      constructor(
        readonly status: number,
        readonly code: string,
        message: string,
        readonly requestId?: string,
      ) {
        super(message)
      }
    },
    setAccessToken: vi.fn(),
    setSessionListener: vi.fn(),
    restoreSession: vi.fn().mockResolvedValue({ accessToken: 'access-token', user }),
    getBootstrap: vi.fn().mockResolvedValue({
      user,
      currentUser: user,
      permissionSnapshot: { permissionKeys: [] },
      branding: {},
    }),
    getAnnouncementInbox: vi.fn().mockResolvedValue({ items: [], unreadCount: 0 }),
    getLoginOptions: vi.fn(),
    getAuthProviders: vi.fn(),
    loginWithProvider: vi.fn(),
    loginWithPassword: vi.fn(),
    logoutServer: vi.fn(),
    markAnnouncementRead: vi.fn(),
    getProfile: vi.fn(),
    updateProfile: vi.fn(),
    changePassword: vi.fn(),
  }
})

let container: HTMLDivElement
let root: Root

const principal = {
  userId: 'user-1',
  userName: 'admin',
  email: 'admin@soha.local',
  roles: [],
  teams: [],
  projects: [],
  tags: [],
}

const hostState = {
  serverUrl: 'https://soha.example.com',
  configurationSource: 'saved' as const,
  managedByEnvironment: false,
  app: {
    name: 'Soha',
    version: 'test',
    platform: 'darwin',
    arch: 'arm64',
    logDirectory: '/tmp/logs',
    updateSupported: false,
  },
}

const bootstrap = {
  user: principal,
  currentUser: principal,
  permissionSnapshot: { permissionKeys: [] },
  branding: {},
}

describe('desktop app', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.mocked(getHostState).mockResolvedValue(hostState)
    vi.mocked(checkServer).mockResolvedValue({
      status: 'online',
      serverUrl: 'https://soha.example.com',
    })
    vi.mocked(clearHostSession).mockResolvedValue(undefined)
    vi.mocked(restoreSession).mockResolvedValue({ accessToken: 'access-token', user: principal })
    vi.mocked(getBootstrap).mockResolvedValue(bootstrap)
    vi.mocked(getAnnouncementInbox).mockResolvedValue({ items: [], unreadCount: 0 })
    vi.mocked(getLoginOptions).mockResolvedValue({
      localPasswordLoginEnabled: true,
      verification: { sliderEnabled: false },
    })
    vi.mocked(getAuthProviders).mockResolvedValue([])
    vi.mocked(loginWithPassword).mockResolvedValue({ accessToken: 'password-token', user: principal })
    vi.mocked(logoutServer).mockResolvedValue(undefined)
    vi.mocked(markAnnouncementRead).mockResolvedValue(undefined)
    vi.mocked(changePassword).mockResolvedValue(undefined)
    localStorage.clear()
    useAppStore.setState({
      host: null,
      connection: null,
      session: null,
      bootstrap: null,
      themeMode: 'system',
      locale: 'zh_CN',
    })
    container = document.createElement('div')
    document.body.appendChild(container)
    root = createRoot(container)
  })

  afterEach(async () => {
    await act(async () => root.unmount())
    container.remove()
  })

  it('restores a session into the App-owned home without Web portal routes', async () => {
    const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    await act(async () => {
      root.render(
        <ConfigProvider>
          <AntApp>
            <QueryClientProvider client={queryClient}>
              <DesktopApp />
            </QueryClientProvider>
          </AntApp>
        </ConfigProvider>,
      )
    })
    await act(async () => {
      await vi.waitFor(() => expect(container.textContent).toContain('首页'))
    })

    expect(container.textContent).toContain('admin')
    expect(container.textContent).toContain('个人资料')
    expect(container.textContent).toContain('设置')
    expect(container.textContent).toContain('当前账号没有查看公告的权限')
    expect(container.querySelector('.status-band')?.getAttribute('aria-label')).toBe('会话状态')
    expect(container.textContent).not.toContain('软件库')
    expect(container.textContent).not.toContain('企业应用')
    expect(getAnnouncementInbox).not.toHaveBeenCalled()
  })

  it('logs in with a password and commits bootstrap before showing home', async () => {
    vi.mocked(restoreSession).mockResolvedValueOnce(null)
    const queryClient = await renderApp()
    await act(async () => {
      await vi.waitFor(() => expect(getLoginOptions).toHaveBeenCalledOnce())
      await vi.waitFor(() => expect(getAuthProviders).toHaveBeenCalledOnce())
      await vi.waitFor(() => expect(queryClient.getQueryState(['auth', 'login-options'])?.status).toBe('success'))
      await vi.waitFor(() => expect(queryClient.getQueryState(['auth', 'providers'])?.status).toBe('success'))
    })
    await waitForUI(() => expect(container.querySelector('input[autocomplete="username"]')).not.toBeNull())

    await setInput(container.querySelector('input[autocomplete="username"]'), 'admin')
    await setInput(container.querySelector('input[autocomplete="current-password"]'), 'secret-password')
    const signIn = findButton(container, '登录')
    expect(signIn).not.toBeNull()
    await act(async () => signIn?.click())
    await act(async () => {
      await vi.waitFor(() => expect(container.textContent).toContain('首页'))
    })

    expect(loginWithPassword).toHaveBeenCalledWith('admin', 'secret-password')
    expect(getBootstrap).toHaveBeenCalledTimes(1)
    expect(useAppStore.getState().session?.accessToken).toBe('password-token')
    expect(useAppStore.getState().bootstrap?.currentUser.userId).toBe('user-1')
  })

  it('treats an unreachable default Server as unconfigured', async () => {
    vi.mocked(getHostState).mockResolvedValueOnce({
      ...hostState,
      serverUrl: 'http://127.0.0.1:8080',
      configurationSource: 'default',
    })
    vi.mocked(checkServer).mockResolvedValueOnce({
      status: 'offline',
      serverUrl: 'http://127.0.0.1:8080',
      code: 'server_unreachable',
    })

    await renderApp()
    await waitForUI(() => expect(container.textContent).toContain('尚未连接组织服务'))

    expect(useAppStore.getState().connection).toMatchObject({
      status: 'unconfigured',
      code: 'server_not_configured',
    })
    expect(container.textContent).toContain('检查并连接')
  })

  it('keeps an online Server distinct when bootstrap fails and retries startup', async () => {
    vi.mocked(getBootstrap)
      .mockRejectedValueOnce(new ApiError(503, 'upstream_unavailable', 'Try again later'))
      .mockResolvedValueOnce(bootstrap)

    await renderApp()
    await waitForUI(() => expect(container.textContent).toContain('无法加载桌面会话'))

    expect(useAppStore.getState().connection?.status).toBe('online')
    expect(container.textContent).not.toContain('尚未连接组织服务')

    await act(async () => findButton(container, '重试')?.click())
    await waitForUI(() => expect(container.textContent).toContain('首页'))

    expect(restoreSession).toHaveBeenCalledTimes(2)
    expect(getBootstrap).toHaveBeenCalledTimes(2)
  })

  it('redirects direct authenticated routes to login without a session', async () => {
    const queryClient = await renderApp(['/settings'])
    await waitForLoginQueries(queryClient)
    await waitForUI(() => expect(container.textContent).toContain('登录 Soha'))

    expect(container.textContent).not.toContain('管理这个桌面客户端的外观')
  })

  it('returns to login with a session-expired message when refresh invalidates the session', async () => {
    const queryClient = await renderAppToHome()
    const listener = vi.mocked(setSessionListener).mock.calls.find(
      ([candidate]) => typeof candidate === 'function',
    )?.[0]
    expect(listener).toBeTypeOf('function')

    await act(async () => listener?.(null))
    await waitForLoginQueries(queryClient)
    await waitForUI(() => expect(document.body.textContent).toContain('会话已过期，请重新登录'))

    expect(useAppStore.getState().session).toBeNull()
    expect(container.textContent).toContain('登录 Soha')
  })

  it('shows a credential error without committing a failed password login', async () => {
    vi.mocked(restoreSession).mockResolvedValueOnce(null)
    vi.mocked(loginWithPassword).mockRejectedValueOnce(new ApiError(401, 'invalid_credentials', 'Unauthorized'))
    const queryClient = await renderApp()
    await waitForLoginQueries(queryClient)
    await waitForUI(() => expect(container.querySelector('input[autocomplete="username"]')).not.toBeNull())

    await setInput(container.querySelector('input[autocomplete="username"]'), 'admin')
    await setInput(container.querySelector('input[autocomplete="current-password"]'), 'wrong-password')
    await act(async () => findButton(container, '登录')?.click())
    await act(async () => {
      await vi.waitFor(() => expect(document.body.textContent).toContain('登录失败，请检查账号和密码'))
    })

    expect(loginWithPassword).toHaveBeenCalledWith('admin', 'wrong-password')
    expect(getBootstrap).not.toHaveBeenCalled()
    expect(useAppStore.getState().session).toBeNull()
  })

  it('requires slider completion and resets it after a failed password login', async () => {
    vi.mocked(restoreSession).mockResolvedValueOnce(null)
    vi.mocked(getLoginOptions).mockResolvedValueOnce({
      localPasswordLoginEnabled: true,
      verification: { sliderEnabled: true },
    })
    vi.mocked(loginWithPassword).mockRejectedValueOnce(new ApiError(401, 'invalid_credentials', 'Unauthorized'))
    const queryClient = await renderApp()
    await waitForLoginQueries(queryClient)
    await waitForUI(() => expect(container.querySelector('[role="slider"]')).not.toBeNull())

    const slider = container.querySelector<HTMLElement>('[role="slider"]')
    const signIn = findButton(container, '登录')
    expect(slider?.getAttribute('aria-label')).toBe('登录验证')
    expect(slider?.getAttribute('aria-valuemin')).toBe('0')
    expect(slider?.getAttribute('aria-valuemax')).toBe('100')
    expect(slider?.getAttribute('aria-valuenow')).toBe('0')
    expect(signIn?.disabled).toBe(true)
    expect(container.querySelector('input[autocomplete="current-password"]')).not.toBeNull()

    await setInput(container.querySelector('input[autocomplete="username"]'), 'admin')
    await setInput(container.querySelector('input[autocomplete="current-password"]'), 'wrong-password')
    await act(async () => {
      container.querySelector('form')?.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }))
    })
    await waitForUI(() => expect(document.body.textContent).toContain('请先完成滑块验证'))
    expect(loginWithPassword).not.toHaveBeenCalled()

    await setSliderFromEnd(slider, 3)
    await waitForUI(() => expect(slider?.getAttribute('aria-valuenow')).toBe('0'))
    expect(signIn?.disabled).toBe(true)

    await setSliderFromEnd(slider, 2)
    await waitForUI(() => {
      expect(slider?.getAttribute('aria-valuenow')).toBe('100')
      expect(container.textContent).toContain('验证完成')
      expect(signIn?.disabled).toBe(false)
    })

    await act(async () => signIn?.click())
    await waitForUI(() => expect(document.body.textContent).toContain('登录失败，请检查账号和密码'))

    expect(loginWithPassword).toHaveBeenCalledWith('admin', 'wrong-password')
    expect(slider?.getAttribute('aria-valuenow')).toBe('0')
    expect(signIn?.disabled).toBe(true)
    expect(getBootstrap).not.toHaveBeenCalled()
    expect(useAppStore.getState().session).toBeNull()
  })

  it('does not start provider login while password login is pending', async () => {
    vi.mocked(restoreSession).mockResolvedValueOnce(null)
    vi.mocked(getAuthProviders).mockResolvedValueOnce([
      { id: 'oidc-main', type: 'oidc', name: 'Corporate OIDC', enabled: true },
    ])
    let resolvePassword!: (session: { accessToken: string; user: typeof principal }) => void
    vi.mocked(loginWithPassword).mockImplementationOnce(
      () => new Promise((resolve) => {
        resolvePassword = resolve
      }),
    )
    const queryClient = await renderApp()
    await waitForLoginQueries(queryClient)
    await waitForUI(() => expect(findButton(container, 'Corporate OIDC')).not.toBeNull())

    await setInput(container.querySelector('input[autocomplete="username"]'), 'admin')
    await setInput(container.querySelector('input[autocomplete="current-password"]'), 'secret-password')
    const signIn = findButton(container, '登录')
    const provider = findButton(container, 'Corporate OIDC')
    await act(async () => {
      signIn?.click()
      provider?.click()
    })

    expect(loginWithPassword).toHaveBeenCalledOnce()
    expect(loginWithProvider).not.toHaveBeenCalled()
    expect(provider?.disabled).toBe(true)

    await act(async () => resolvePassword({ accessToken: 'password-token', user: principal }))
    await waitForUI(() => expect(container.textContent).toContain('首页'))
  })

  it('hides password fields when local login is disabled and keeps enabled providers', async () => {
    vi.mocked(restoreSession).mockResolvedValueOnce(null)
    vi.mocked(getLoginOptions).mockResolvedValueOnce({
      localPasswordLoginEnabled: false,
      verification: { sliderEnabled: false },
    })
    vi.mocked(getAuthProviders).mockResolvedValueOnce([
      { id: 'oidc-main', type: 'oidc', name: 'Corporate OIDC', enabled: true },
      { id: 'disabled', type: 'oidc', name: 'Disabled Provider', enabled: false },
    ])
    const queryClient = await renderApp()
    await waitForLoginQueries(queryClient)
    await waitForUI(() => expect(container.textContent).toContain('此组织未启用本地密码登录'))

    expect(container.querySelector('input[autocomplete="current-password"]')).toBeNull()
    expect(container.textContent).toContain('Corporate OIDC')
    expect(container.textContent).not.toContain('Disabled Provider')
  })

  it('cancels a pending provider login without creating a session', async () => {
    vi.mocked(restoreSession).mockResolvedValueOnce(null)
    vi.mocked(getAuthProviders).mockResolvedValueOnce([
      { id: 'oidc-main', type: 'oidc', name: 'Corporate OIDC', enabled: true },
    ])
    let providerSignal: AbortSignal | undefined
    vi.mocked(loginWithProvider).mockImplementationOnce(
      (_providerId, signal) =>
        new Promise((_resolve, reject) => {
          providerSignal = signal
          signal.addEventListener(
            'abort',
            () => reject(new DOMException('Aborted', 'AbortError')),
            { once: true },
          )
        }),
    )
    const queryClient = await renderApp()
    await waitForLoginQueries(queryClient)

    await waitForUI(() => expect(findButton(container, 'Corporate OIDC')).not.toBeNull())
    const providerButton = findButton(container, 'Corporate OIDC')
    expect(providerButton).not.toBeNull()
    await act(async () => providerButton?.dispatchEvent(new MouseEvent('click', { bubbles: true, cancelable: true })))
    expect(loginWithProvider).toHaveBeenCalledOnce()
    await waitForUI(() => expect(container.textContent).toContain('正在完成组织登录'))
    expect(providerSignal?.aborted).toBe(false)

    await act(async () => findButton(container, '取消')?.click())
    await act(async () => {
      await vi.waitFor(() => expect(providerSignal?.aborted).toBe(true))
      await vi.waitFor(() => expect(findButton(container, 'Corporate OIDC')).not.toBeNull())
    })
    expect(getBootstrap).not.toHaveBeenCalled()
    expect(useAppStore.getState().session).toBeNull()
  })

  it('clears local session and queries when remote logout fails', async () => {
    vi.mocked(logoutServer).mockRejectedValueOnce(new Error('offline'))
    const queryClient = await renderAppToHome()
    queryClient.setQueryData(['private'], { secret: true })

    const logout = findButton(container, '退出登录')
    expect(logout).not.toBeNull()
    await act(async () => logout?.click())
    await act(async () => {
      await vi.waitFor(() => expect(getLoginOptions).toHaveBeenCalledOnce())
      await vi.waitFor(() => expect(getAuthProviders).toHaveBeenCalledOnce())
      await vi.waitFor(() => expect(queryClient.getQueryState(['auth', 'login-options'])?.status).toBe('success'))
      await vi.waitFor(() => expect(queryClient.getQueryState(['auth', 'providers'])?.status).toBe('success'))
    })

    expect(logoutServer).toHaveBeenCalledOnce()
    expect(clearHostSession).toHaveBeenCalledOnce()
    expect(useAppStore.getState().session).toBeNull()
    expect(useAppStore.getState().bootstrap).toBeNull()
    expect(queryClient.getQueryData(['private'])).toBeUndefined()
  })

  it('shows a foreground connection failure and recovers on retry', async () => {
    const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    await act(async () => {
      root.render(
        <ConfigProvider>
          <AntApp>
            <QueryClientProvider client={queryClient}>
              <DesktopApp />
            </QueryClientProvider>
          </AntApp>
        </ConfigProvider>,
      )
    })
    await act(async () => {
      await vi.waitFor(() => expect(container.querySelector('.connection-indicator.online')).not.toBeNull())
    })

    vi.mocked(checkServer).mockResolvedValueOnce({
      status: 'offline',
      serverUrl: 'https://soha.example.com',
      code: 'server_unreachable',
    })
    await act(async () => {
      document.dispatchEvent(new Event('visibilitychange'))
    })
    await act(async () => {
      await vi.waitFor(() => expect(container.querySelector('.connection-indicator.offline')).not.toBeNull())
    })
    expect(container.querySelector('.connection-indicator')?.textContent).toContain('无法连接服务')

    const retry = container.querySelector<HTMLButtonElement>('button[aria-label="重试"]')
    expect(retry).not.toBeNull()
    await act(async () => retry?.click())
    await act(async () => {
      await vi.waitFor(() => expect(container.querySelector('.connection-indicator.online')).not.toBeNull())
    })
    expect(container.querySelector('.connection-indicator')?.textContent).toContain('已连接')
  })

  it('requests announcements only with permission and marks an unread item', async () => {
    vi.mocked(getBootstrap).mockResolvedValueOnce({
      ...bootstrap,
      permissionSnapshot: { permissionKeys: ['system.announcements.view'] },
    })
    vi.mocked(getAnnouncementInbox).mockResolvedValue({
      unreadCount: 1,
      items: [{
        id: 'announcement-1',
        title: 'Maintenance notice',
        summary: 'Planned maintenance',
        level: 'info',
        isRead: false,
      }],
    })
    const queryClient = await renderAppToHome()
    await act(async () => {
      await vi.waitFor(() => expect(getAnnouncementInbox).toHaveBeenCalledWith(5), { timeout: 3_000 })
      await vi.waitFor(
        () => expect(queryClient.getQueryState(['announcements', 'inbox'])?.status).toBe('success'),
        { timeout: 3_000 },
      )
    })
    await waitForUI(() => expect(container.textContent).toContain('Maintenance notice'))

    expect(getAnnouncementInbox).toHaveBeenCalledWith(5)
    const markRead = container.querySelector<HTMLButtonElement>('button[aria-label="标记为已读: Maintenance notice"]')
    expect(markRead).not.toBeNull()
    await act(async () => markRead?.click())
    await act(async () => {
      await vi.waitFor(() => expect(vi.mocked(markAnnouncementRead).mock.calls[0]?.[0]).toBe('announcement-1'))
    })
  })

  it('distinguishes and retries an unavailable announcement service', async () => {
    vi.mocked(getBootstrap).mockResolvedValueOnce({
      ...bootstrap,
      permissionSnapshot: { permissionKeys: ['system.announcements.view'] },
    })
    vi.mocked(getAnnouncementInbox)
      .mockRejectedValueOnce(new ApiError(503, 'upstream_unavailable', 'Try again later', 'announcement-request'))
      .mockResolvedValueOnce({ items: [], unreadCount: 0 })
    const queryClient = await renderAppToHome()

    await act(async () => {
      await vi.waitFor(
        () => expect(queryClient.getQueryState(['announcements', 'inbox'])?.status).toBe('error'),
        { timeout: 3_000 },
      )
    })
    await waitForUI(() => expect(container.textContent).toContain('公告服务暂时不可用'))
    expect(container.textContent).toContain('请求 ID: announcement-request')

    await act(async () => findButton(container, '重试')?.click())
    await act(async () => {
      await vi.waitFor(() => expect(getAnnouncementInbox).toHaveBeenCalledTimes(2))
      await vi.waitFor(() => expect(queryClient.getQueryState(['announcements', 'inbox'])?.status).toBe('success'))
    })
    await waitForUI(() => expect(container.textContent).toContain('暂无公告'))
  })

  it('retries a failed profile and keeps external identities out of the password form', async () => {
    let rejectProfile: ((reason?: unknown) => void) | undefined
    let resolveProfile: ((profile: Awaited<ReturnType<typeof getProfile>>) => void) | undefined
    const externalProfile = {
      userId: 'user-1',
      username: 'admin',
      displayName: 'Admin',
      email: 'admin@soha.local',
      status: 'active',
      roles: [],
      teams: [],
      projects: [],
      tags: [],
      identities: [{ providerType: 'oidc', providerId: 'corp-oidc', displayName: 'Corporate OIDC' }],
    }
    vi.mocked(getProfile)
      .mockImplementationOnce(
        () =>
          new Promise((_, reject) => {
            rejectProfile = reject
          }),
      )
      .mockImplementationOnce(
        () =>
          new Promise((resolve) => {
            resolveProfile = resolve
          }),
      )
    const queryClient = await renderAppToHome()

    await clickNavigation('个人资料')
    await act(async () => {
      await vi.waitFor(() => expect(getProfile).toHaveBeenCalledTimes(1))
      expect(rejectProfile).toBeTypeOf('function')
      rejectProfile?.(new Error('offline'))
      await vi.waitFor(() => expect(queryClient.getQueryState(['auth', 'profile'])?.status).toBe('error'))
    })
    await act(async () => {
      await vi.waitFor(() => expect(container.textContent).toContain('无法连接服务'))
    })
    await act(async () => {
      await vi.waitFor(() => expect(findButton(container, '重试')).not.toBeNull())
    })
    const retry = findButton(container, '重试')
    await act(async () => retry?.dispatchEvent(new MouseEvent('click', { bubbles: true, cancelable: true })))
    await act(async () => {
      await vi.waitFor(() => expect(getProfile).toHaveBeenCalledTimes(2))
      expect(resolveProfile).toBeTypeOf('function')
      resolveProfile?.(externalProfile)
      await vi.waitFor(() => expect(queryClient.getQueryState(['auth', 'profile'])?.status).toBe('success'))
    })
    await act(async () => {
      await vi.waitFor(() => expect(container.textContent).toContain('Corporate OIDC'))
    })

    expect(container.textContent).toContain('此账号没有本地密码身份')
    expect(container.querySelector('input[autocomplete="current-password"]')).toBeNull()
  })

  it('updates only editable profile fields and changes a local password', async () => {
    const profile = {
      userId: 'user-1',
      username: 'admin',
      displayName: 'Admin',
      email: 'admin@soha.local',
      phone: '13800000000',
      avatarUrl: 'https://example.com/avatar.png',
      avatarFit: 'contain',
      status: 'active',
      roles: ['admin'],
      teams: [],
      projects: [],
      tags: [],
      identities: [{ providerType: 'password', providerId: 'local', displayName: 'Password' }],
    }
    const updated = { ...profile, displayName: 'Updated Admin' }
    vi.mocked(getProfile).mockResolvedValue(profile)
    vi.mocked(updateProfile).mockResolvedValueOnce(updated)
    const queryClient = await renderAppToHome()
    await clickNavigation('个人资料')
    await act(async () => {
      await vi.waitFor(
        () => expect(queryClient.getQueryState(['auth', 'profile'])?.status).toBe('success'),
        { timeout: 3_000 },
      )
    })
    await waitForUI(() => expect(container.querySelector('input[autocomplete="name"]')).not.toBeNull())
    expect(container.textContent).toContain('完整显示')

    await setInput(container.querySelector('input[autocomplete="name"]'), updated.displayName)
    await act(async () => findButton(container, '保存')?.click())
    await act(async () => {
      await vi.waitFor(() => expect(updateProfile).toHaveBeenCalledOnce())
    })
    expect(vi.mocked(updateProfile).mock.calls[0]?.[0]).toEqual({
      displayName: updated.displayName,
      email: profile.email,
      phone: profile.phone,
      avatarUrl: profile.avatarUrl,
      avatarFit: profile.avatarFit,
    })
    expect(useAppStore.getState().session?.user.displayName).toBe(updated.displayName)

    await setInput(container.querySelector('input[autocomplete="current-password"]'), 'current-secret')
    const newPasswordInputs = container.querySelectorAll<HTMLInputElement>('input[autocomplete="new-password"]')
    await setInput(newPasswordInputs.item(0), 'new-password')
    await setInput(newPasswordInputs.item(1), 'different-password')
    await act(async () => findButton(container, '修改密码')?.click())
    await act(async () => {
      await vi.waitFor(() => expect(document.body.textContent).toContain('两次输入的新密码不一致'))
    })
    expect(changePassword).not.toHaveBeenCalled()

    await setInput(newPasswordInputs.item(1), 'new-password')
    await act(async () => findButton(container, '修改密码')?.click())
    await act(async () => {
      await vi.waitFor(() => expect(changePassword).toHaveBeenCalledWith('current-secret', 'new-password'))
    })
    await act(async () => {
      await vi.waitFor(() => expect(container.querySelector<HTMLInputElement>('input[autocomplete="current-password"]')?.value).toBe(''))
    })
  })

  it('keeps the current session when a new Server fails validation', async () => {
    await renderAppToHome()
    await clickNavigation('设置')
    vi.mocked(checkServer).mockResolvedValueOnce({
      status: 'offline',
      serverUrl: 'https://new-soha.example.com',
      code: 'server_unreachable',
    })

    await act(async () => {
      await vi.waitFor(() => expect(findButton(container, '更换 Server')).not.toBeNull())
    })
    const changeServer = findButton(container, '更换 Server')
    await act(async () => changeServer?.click())
    await act(async () => {
      await vi.waitFor(() => expect(document.querySelector('.ant-modal input')).not.toBeNull())
    })
    const input = document.querySelector<HTMLInputElement>('.ant-modal input')
    await act(async () => {
      const setValue = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set
      setValue?.call(input, 'https://new-soha.example.com')
      input?.dispatchEvent(new Event('input', { bubbles: true }))
    })
    const confirm = document.querySelector<HTMLButtonElement>('.ant-modal .ant-btn-primary')
    expect(confirm).not.toBeNull()
    await act(async () => confirm?.click())
    await act(async () => {
      await vi.waitFor(() => expect(document.body.textContent).toContain('确认服务已启动且网络可达后重试'))
    })

    expect(prepareServerSwitch).not.toHaveBeenCalled()
    expect(useAppStore.getState().session?.user.userId).toBe('user-1')
  })

  it('clears the old session before activating a validated Server switch', async () => {
    const queryClient = await renderAppToHome()
    queryClient.setQueryData(['private'], { secret: true })
    await clickNavigation('设置')
    const nextConnection = { status: 'online' as const, serverUrl: 'https://new-soha.example.com' }
    vi.mocked(checkServer).mockResolvedValueOnce(nextConnection)
    vi.mocked(prepareServerSwitch).mockResolvedValueOnce({
      activationToken: 'activate-new-server',
      connection: nextConnection,
    })
    vi.mocked(activateServerSwitch).mockResolvedValueOnce({
      ...hostState,
      serverUrl: nextConnection.serverUrl,
      configurationSource: 'runtime',
    })

    await act(async () => {
      await vi.waitFor(() => expect(findButton(container, '更换 Server')).not.toBeNull())
    })
    await act(async () => findButton(container, '更换 Server')?.click())
    await act(async () => {
      await vi.waitFor(() => expect(document.querySelector('.ant-modal input')).not.toBeNull())
    })
    await setInput(document.querySelector('.ant-modal input'), nextConnection.serverUrl)
    await waitForUI(() => {
      expect(document.body.textContent).toContain(hostState.serverUrl)
      expect(document.body.textContent).toContain(nextConnection.serverUrl)
      expect(document.body.textContent).toContain('新的 Server')
    })
    const confirm = document.querySelector<HTMLButtonElement>('.ant-modal .ant-btn-primary')
    await act(async () => confirm?.click())
    await act(async () => {
      await vi.waitFor(() => expect(activateServerSwitch).toHaveBeenCalledOnce())
      await vi.waitFor(() => expect(getLoginOptions).toHaveBeenCalledOnce())
      await vi.waitFor(() => expect(getAuthProviders).toHaveBeenCalledOnce())
      await vi.waitFor(() => expect(queryClient.getQueryState(['auth', 'login-options'])?.status).toBe('success'))
      await vi.waitFor(() => expect(queryClient.getQueryState(['auth', 'providers'])?.status).toBe('success'))
    })

    expect(prepareServerSwitch).toHaveBeenCalledWith(nextConnection.serverUrl, 'access-token')
    expect(activateServerSwitch).toHaveBeenCalledWith('activate-new-server')
    expect(useAppStore.getState().host?.serverUrl).toBe(nextConnection.serverUrl)
    expect(useAppStore.getState().session).toBeNull()
    expect(queryClient.getQueryData(['private'])).toBeUndefined()
  })

  it('keeps old credentials cleared when Server activation fails', async () => {
    const queryClient = await renderAppToHome()
    queryClient.setQueryData(['private'], { secret: true })
    await clickNavigation('设置')
    const nextConnection = { status: 'online' as const, serverUrl: 'https://new-soha.example.com' }
    vi.mocked(checkServer)
      .mockResolvedValueOnce(nextConnection)
      .mockResolvedValueOnce({ status: 'online', serverUrl: hostState.serverUrl })
    vi.mocked(prepareServerSwitch).mockResolvedValueOnce({
      activationToken: 'activate-new-server',
      connection: nextConnection,
    })
    vi.mocked(activateServerSwitch).mockRejectedValueOnce(new Error('activation failed'))

    await act(async () => findButton(container, '更换 Server')?.click())
    await waitForUI(() => expect(document.querySelector('.ant-modal input')).not.toBeNull())
    await setInput(document.querySelector('.ant-modal input'), nextConnection.serverUrl)
    await act(async () => document.querySelector<HTMLButtonElement>('.ant-modal .ant-btn-primary')?.click())
    await waitForUI(() => expect(container.textContent).toContain('登录 Soha'))

    expect(getHostState).toHaveBeenCalledTimes(2)
    expect(useAppStore.getState().host?.serverUrl).toBe(hostState.serverUrl)
    expect(useAppStore.getState().session).toBeNull()
    expect(queryClient.getQueryData(['private'])).toBeUndefined()
  })

  it('provides a skip link and moves focus to main content after navigation', async () => {
    await renderAppToHome()
    const skipLink = container.querySelector<HTMLAnchorElement>('a.skip-link')
    const main = container.querySelector<HTMLElement>('#main-content')

    expect(skipLink?.getAttribute('href')).toMatch(/#main-content$/)
    expect(skipLink?.textContent).toBe('跳到主内容')
    expect(main?.getAttribute('tabindex')).toBe('-1')

    await clickNavigation('个人资料')
    await waitForUI(() => expect(container.textContent).toContain('查看和更新你的个人资料'))

    expect(document.activeElement).toBe(main)
  })

  it('keeps a managed Server fixed, persists appearance preferences, and reports updates unavailable', async () => {
    vi.mocked(getHostState).mockResolvedValueOnce({
      ...hostState,
      configurationSource: 'environment',
      managedByEnvironment: true,
    })
    await renderAppToHome()
    await clickNavigation('设置')
    await act(async () => {
      await vi.waitFor(() => expect(container.textContent).toContain('环境变量管理'))
    })

    expect(findButton(container, '更换 Server')).toBeNull()
    expect(container.textContent).toContain('当前构建未配置签名更新源')
    await clickSegmentedOption('深色')
    await clickSegmentedOption('English')
    await act(async () => {
      await vi.waitFor(() => expect(useAppStore.getState().themeMode).toBe('dark'))
      await vi.waitFor(() => expect(useAppStore.getState().locale).toBe('en_US'))
    })
    expect(container.textContent).toContain('Appearance and language')
    expect(container.textContent).not.toContain('外观与语言')
    await clickNavigation('Home')
    await waitForUI(() => expect(container.textContent).toContain('Review the current server status'))
    expect(container.textContent).not.toContain('查看当前服务状态')
    await clickNavigation('Profile')
    await waitForUI(() => expect(container.textContent).toContain('View and update your profile'))
    expect(container.textContent).not.toContain('查看和更新你的个人资料')
    const persisted = localStorage.getItem('soha-app-preferences') || ''
    expect(persisted).toContain('dark')
    expect(persisted).toContain('en_US')
  })
})

async function renderAppToHome() {
  const queryClient = await renderApp()
  await act(async () => {
    await vi.waitFor(() => expect(container.textContent).toContain('首页'), { timeout: 3_000 })
  })
  return queryClient
}

async function renderApp(initialEntries?: string[]) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  await act(async () => {
    root.render(
      <ConfigProvider>
        <AntApp>
          <QueryClientProvider client={queryClient}>
              <DesktopApp initialEntries={initialEntries} />
          </QueryClientProvider>
        </AntApp>
      </ConfigProvider>,
      )
    })
  return queryClient
}

async function waitForLoginQueries(queryClient: QueryClient) {
  await act(async () => {
    await vi.waitFor(() => expect(getLoginOptions).toHaveBeenCalledOnce())
    await vi.waitFor(() => expect(getAuthProviders).toHaveBeenCalledOnce())
    await vi.waitFor(() => expect(queryClient.getQueryState(['auth', 'login-options'])?.status).toBe('success'))
    await vi.waitFor(() => expect(queryClient.getQueryState(['auth', 'providers'])?.status).toBe('success'))
  })
}

async function clickNavigation(label: string) {
  const link = Array.from(container.querySelectorAll<HTMLAnchorElement>('a')).find(
    (candidate) => candidate.textContent?.trim() === label,
  )
  expect(link).toBeDefined()
  await act(async () => link?.click())
}

async function clickSegmentedOption(label: string) {
  const option = Array.from(container.querySelectorAll<HTMLElement>('.ant-segmented-item')).find(
    (candidate) => candidate.textContent?.trim() === label,
  )
  expect(option).toBeDefined()
  await act(async () => option?.click())
}

async function waitForUI(assertion: () => void) {
  await vi.waitFor(async () => {
    await act(async () => {
      await new Promise((resolve) => setTimeout(resolve, 0))
    })
    assertion()
  }, { timeout: 3_000 })
}

async function setSliderFromEnd(slider: HTMLElement | null, stepsFromEnd: number) {
  expect(slider).not.toBeNull()
  await dispatchSliderKey(slider, 'keydown', 'End', 35)
  for (let step = 0; step < stepsFromEnd; step += 1) {
    await dispatchSliderKey(slider, 'keydown', 'ArrowLeft', 37)
  }
  await dispatchSliderKey(slider, 'keyup', stepsFromEnd ? 'ArrowLeft' : 'End', stepsFromEnd ? 37 : 35)
}

async function dispatchSliderKey(
  slider: HTMLElement | null,
  type: 'keydown' | 'keyup',
  key: string,
  keyCode: number,
) {
  await act(async () => {
    const event = new KeyboardEvent(type, { bubbles: true, cancelable: true, key })
    Object.defineProperties(event, {
      keyCode: { value: keyCode },
      which: { value: keyCode },
    })
    slider?.dispatchEvent(event)
  })
}

function findButton(rootElement: ParentNode, label: string): HTMLButtonElement | null {
  const normalizedLabel = label.replace(/\s+/g, '')
  return (
    Array.from(rootElement.querySelectorAll<HTMLButtonElement>('button')).find(
      (button) => button.textContent?.replace(/\s+/g, '').includes(normalizedLabel),
    ) || null
  )
}

async function setInput(input: HTMLInputElement | null, value: string) {
  expect(input).not.toBeNull()
  await act(async () => {
    const setValue = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set
    setValue?.call(input, value)
    input?.dispatchEvent(new Event('input', { bubbles: true }))
  })
}
