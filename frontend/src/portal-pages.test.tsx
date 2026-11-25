/** @vitest-environment jsdom */

import { act } from 'react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { createRoot, type Root } from 'react-dom/client'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { App as AntApp } from 'antd'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { PortalApplicationPage, PortalPage } from '@/portal-pages'
import {
  ApiError,
  getPortalApplication,
  getPortalBootstrap,
  getPortalColleagueApps,
  launchPortalApplication,
  setPortalFavorite,
} from '@/api'
import { openBrowserURL } from '@/native/host'
import { useAppStore } from '@/store'

vi.mock('@/api', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@/api')>()
  return {
    ...actual,
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
    getPortalApplication: vi.fn(),
    getPortalBootstrap: vi.fn(),
    getPortalColleagueApps: vi.fn(),
    launchPortalApplication: vi.fn(),
    setPortalFavorite: vi.fn(),
  }
})

vi.mock('@/native/host', () => ({ openBrowserURL: vi.fn() }))

const application = {
  id: 'app-1',
  slug: 'workspace-slug',
  name: 'Soha Console',
  description: 'Operations console',
  category: 'console',
  tags: ['console', 'recommended'],
  providerType: 'proxy' as const,
  status: 'enabled' as const,
  favorite: false,
  metadata: { tenant: 'default' },
  lastLaunchedAt: '2026-08-31T00:59:00Z',
  createdAt: '2026-08-31T01:00:00Z',
  updatedAt: '2026-08-31T01:00:00Z',
}
const favoriteApplication = {
  ...application,
  id: 'app-2',
  slug: 'favorite-console',
  name: 'Favorite Console',
  favorite: true,
}
const bootstrap = {
  principal: {
    userId: 'user-1',
    userName: 'OpenSoha',
    email: 'opensoha@soha.local',
    roles: [],
    teams: [],
    projects: [],
    tags: [],
  },
  applications: [application, favoriteApplication],
  favorites: [favoriteApplication],
  recent: [],
  categories: ['console', 'oidc'],
  security: {
    principal: {
      userId: 'user-1',
      userName: 'OpenSoha',
      email: 'opensoha@soha.local',
      roles: [],
      teams: [],
      projects: [],
      tags: [],
    },
    mfaEnabled: false,
    linkedSources: [],
    activeSession: 1,
  },
}

const roots: Root[] = []

async function renderPortal(path = '/portal') {
  const container = document.createElement('div')
  document.body.appendChild(container)
  const root = createRoot(container)
  roots.push(root)
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  await act(async () => {
    root.render(
      <AntApp>
        <QueryClientProvider client={queryClient}>
          <MemoryRouter initialEntries={[path]}>
            <Routes>
              <Route path="/portal" element={<PortalPage />} />
              <Route
                path="/portal/applications/:applicationId"
                element={<PortalApplicationPage />}
              />
            </Routes>
          </MemoryRouter>
        </QueryClientProvider>
      </AntApp>,
    )
  })
  return container
}

async function waitForText(container: HTMLElement, value: string) {
  await vi.waitFor(async () => {
    await act(async () => {
      await new Promise((resolve) => setTimeout(resolve, 0))
    })
    expect(container.textContent).toContain(value)
  })
}

beforeEach(() => {
  vi.clearAllMocks()
  vi.mocked(getPortalBootstrap).mockResolvedValue(bootstrap)
  vi.mocked(getPortalApplication).mockResolvedValue(application)
  vi.mocked(getPortalColleagueApps).mockResolvedValue({
    items: [],
    authors: [],
    myAppsCount: 0,
    total: 0,
  })
  vi.mocked(setPortalFavorite).mockResolvedValue({ ...application, favorite: true })
  vi.mocked(launchPortalApplication).mockResolvedValue({
    application,
    launchUrl: '/auth/browser-handoff/handoff-1',
    providerType: 'link',
    decision: 'allow',
    handoffExpiresAt: '2026-08-31T01:01:00Z',
  })
  vi.mocked(openBrowserURL).mockResolvedValue(undefined)
  useAppStore.setState({
    bootstrap: null,
    host: {
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
    },
    locale: 'zh_CN',
    portalCardSize: 'standard',
  })
})

afterEach(async () => {
  await act(async () => {
    for (const root of roots.splice(0)) root.unmount()
  })
  document.body.innerHTML = ''
})

describe('desktop provider portal', () => {
  it('shows authorized applications and filters locally without expanding the result set', async () => {
    const container = await renderPortal()
    expect(getPortalBootstrap).toHaveBeenCalledOnce()
    await waitForText(container, 'Soha Console')
    expect(container.querySelector('.page-heading')).toBeNull()
    expect(container.querySelector('h1.visually-hidden')?.textContent).toBe('应用门户')

    const search = container.querySelector<HTMLInputElement>('input[placeholder="搜索应用"]')
    await act(async () => {
      if (!search) return
      Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set?.call(search, 'workspace-slug')
      search.dispatchEvent(new Event('input', { bubbles: true }))
    })
    expect(container.textContent).toContain('Soha Console')

    await act(async () => {
      if (!search) return
      Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set?.call(search, 'proxy')
      search.dispatchEvent(new Event('input', { bubbles: true }))
    })
    expect(container.textContent).toContain('Soha Console')

    await act(async () => {
      if (!search) return
      Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set?.call(search, 'missing')
      search.dispatchEvent(new Event('input', { bubbles: true }))
    })

    await waitForText(container, '没有匹配的应用')
    expect(container.textContent).not.toContain('Operations console')
  })

  it('fills missing provider groups and resolves application image links safely', async () => {
    const platformApplication = {
      ...application,
      category: 'Platform',
      iconUrl: '/assets/console.png',
      providerType: 'link' as const,
    }
    const oidcApplication = {
      ...favoriteApplication,
      category: '',
      iconUrl: 'data:image/png;base64,iVBORw==',
      name: 'OIDC Application',
      providerType: 'oidc' as const,
    }
    const proxyApplication = {
      ...application,
      id: 'app-3',
      category: '',
      iconUrl: 'javascript:alert(1)',
      name: 'Proxy Application',
      providerType: 'proxy' as const,
    }
    vi.mocked(getPortalBootstrap).mockResolvedValueOnce({
      ...bootstrap,
      applications: [platformApplication, oidcApplication, proxyApplication],
      categories: ['Platform'],
      favorites: [oidcApplication],
    })

    const container = await renderPortal()
    await waitForText(container, 'Proxy Application')

    const group = container.querySelector<HTMLElement>('[role="group"][aria-label="分组"]')
    const labels = [...(group?.querySelectorAll('button') || [])]
      .map((button) => button.textContent?.replace(/ /g, ''))
    expect(labels).toEqual(expect.arrayContaining(['全部', 'Platform', 'oidc', 'proxy']))
    expect(container.querySelector<HTMLImageElement>('img[alt="Soha Console"]')?.src)
      .toBe('https://soha.example.com/assets/console.png')
    expect(container.querySelector<HTMLImageElement>('img[alt="OIDC Application"]')?.src)
      .toBe('data:image/png;base64,iVBORw==')
    expect(container.querySelector('img[alt="Proxy Application"]')).toBeNull()

    const oidc = [...(group?.querySelectorAll('button') || [])]
      .find((button) => button.textContent === 'oidc')
    await act(async () => oidc?.click())

    const cards = [...container.querySelectorAll<HTMLElement>('.portal-card')]
    expect(cards).toHaveLength(1)
    expect(cards[0]?.textContent).toContain('OIDC Application')
  })

  it('shows a localized error state when the Server is unreachable', async () => {
    vi.mocked(getPortalBootstrap).mockRejectedValueOnce(
      new ApiError(0, 'network_error', 'Soha server is unavailable'),
    )

    const container = await renderPortal()
    await waitForText(container, '无法连接服务')

    expect(container.textContent).toContain('确认服务已启动且网络可达后重试。')
    expect(container.textContent).not.toContain('暂无应用')
    expect(container.querySelector('.ant-alert-error')).not.toBeNull()
    expect(container.querySelector('.page-heading')).toBeNull()
  })

  it('persists favorites through the Server', async () => {
    const container = await renderPortal()
    await waitForText(container, 'Soha Console')
    const favorite = container.querySelector<HTMLButtonElement>('button[aria-label="收藏 Soha Console"]')

    await act(async () => favorite?.click())

    expect(setPortalFavorite).toHaveBeenCalledWith('app-1', true)
    expect(launchPortalApplication).not.toHaveBeenCalled()
  })

  it('switches between all applications and favorites without secondary summaries', async () => {
    const container = await renderPortal()
    await waitForText(container, 'Favorite Console')

    expect(container.textContent).toContain('Soha Console')
    expect(container.textContent).not.toContain('最近访问')
    expect(container.textContent).not.toContain('账号安全')

    const favorites = [...container.querySelectorAll<HTMLElement>('.ant-segmented-item')]
      .find((item) => item.textContent?.includes('收藏'))
    await act(async () => favorites?.click())

    expect(container.textContent).toContain('Favorite Console')
    expect(container.textContent).not.toContain('Soha Console')
  })

  it('uses the card size selected in Settings without showing a portal control', async () => {
    useAppStore.setState({ portalCardSize: 'compact' })
    const container = await renderPortal()
    await waitForText(container, 'Soha Console')

    const grid = container.querySelector<HTMLElement>('.portal-grid')
    expect(container.querySelector('[aria-label="卡片尺寸"]')).toBeNull()
    expect(grid?.classList.contains('compact')).toBe(true)
    expect(container.textContent).not.toContain('Operations console')
  })

  it('launches desktop surface and opens only the returned same-origin handoff URL', async () => {
    const storageWrite = vi.spyOn(Storage.prototype, 'setItem')
    const container = await renderPortal()
    await waitForText(container, 'Soha Console')
    const open = container.querySelector<HTMLButtonElement>('button[aria-label="打开 Soha Console"]')
    expect(open).not.toBeNull()

    await act(async () => open?.click())
    await act(async () => {
      await vi.waitFor(() => expect(openBrowserURL).toHaveBeenCalledOnce())
    })

    expect(launchPortalApplication).toHaveBeenCalledWith('app-1')
    expect(openBrowserURL).toHaveBeenCalledWith(
      'https://soha.example.com/auth/browser-handoff/handoff-1',
    )
    expect(storageWrite).not.toHaveBeenCalled()
    storageWrite.mockRestore()
  })

  it('does not open a browser when launch is rejected', async () => {
    vi.mocked(launchPortalApplication).mockRejectedValueOnce(new Error('launch denied'))
    const container = await renderPortal()
    await waitForText(container, 'Soha Console')
    const open = container.querySelector<HTMLButtonElement>('button[aria-label="打开 Soha Console"]')

    await act(async () => open?.click())

    expect(launchPortalApplication).toHaveBeenCalledWith('app-1')
    expect(openBrowserURL).not.toHaveBeenCalled()
  })

  it('loads application detail from the protected detail operation', async () => {
    const container = await renderPortal('/portal/applications/app-1')
    await waitForText(container, 'Operations console')

    expect(getPortalApplication).toHaveBeenCalledWith('app-1')
    expect(container.textContent).toContain('recommended')
    expect(container.textContent).toContain('proxy')
    expect(container.textContent).toContain('2026-08-31T00:59:00Z')
    expect(container.textContent).toContain('default')
  })

  it('shows Web my-apps shortcut when permitted or myAppsCount > 0 and opens safe Web URL', async () => {
    vi.mocked(getPortalColleagueApps).mockResolvedValue({
      items: [],
      authors: [],
      myAppsCount: 2,
      total: 0,
    })

    const container = await renderPortal()
    await waitForText(container, '我的作品 (2)')

    const myAppsButton = container.querySelector<HTMLButtonElement>('button[aria-label="我的作品"]')
    expect(myAppsButton).not.toBeNull()
    await act(async () => myAppsButton?.click())

    await vi.waitFor(() =>
      expect(openBrowserURL).toHaveBeenCalledWith('https://soha.example.com/portal/my-apps'),
    )
  })

  it('browses colleague works, distinguishes same-name authors by department, drills into author works, and validates external URLs', async () => {
    const zhangMarket = {
      userId: 'user-zhang-market',
      displayName: '张伟',
      teamNames: ['市场部'],
      visibleAppCount: 2,
    }
    const zhangFinance = {
      userId: 'user-zhang-finance',
      displayName: '张伟',
      teamNames: ['财务部'],
      visibleAppCount: 1,
    }
    const scheduleTool = {
      id: 'hosted-schedule',
      name: '市场排班看板',
      description: '大促活动排班与值班日历',
      kind: 'static' as const,
      dnsLabel: 'schedule-1a2b',
      host: 'schedule-1a2b.apps.example.com',
      url: 'https://schedule-1a2b.apps.example.com/',
      author: {
        userId: zhangMarket.userId,
        displayName: zhangMarket.displayName,
        teamNames: zhangMarket.teamNames,
      },
      updatedAt: '2026-11-21T03:00:00Z',
    }
    const unsafeTool = {
      ...scheduleTool,
      id: 'hosted-unsafe',
      name: 'Unsafe Tool',
      kind: 'dynamic' as const,
      url: 'javascript:alert(1)',
    }

    let authorRevoked = false
    vi.mocked(getPortalColleagueApps).mockImplementation(async (params) => {
      if (params?.offset === 24) {
        return {
          items: [{ ...scheduleTool, id: 'hosted-next', name: '第二页作品' }],
          authors: [],
          myAppsCount: 0,
          total: 25,
        }
      }
      if (params?.authorUserId === 'user-zhang-market') {
        if (authorRevoked) return { items: [], authors: [], myAppsCount: 0, total: 0 }
        return {
          items: [scheduleTool],
          authors: [],
          selectedAuthor: zhangMarket,
          myAppsCount: 0,
          total: 1,
        }
      }
      if (params?.kind === 'dynamic') {
        return {
          items: [unsafeTool],
          authors: [],
          myAppsCount: 0,
          total: 1,
        }
      }
      if (params?.query === '张伟') {
        return {
          items: [scheduleTool],
          authors: [zhangMarket, zhangFinance],
          myAppsCount: 0,
          total: 1,
        }
      }
      return {
        items: [scheduleTool],
        authors: [],
        myAppsCount: 0,
        total: 25,
      }
    })

    const container = await renderPortal()
    await waitForText(container, 'Soha Console')

    const colleagueTab = [...container.querySelectorAll<HTMLElement>('.ant-segmented-item')].find(
      (item) => item.textContent?.includes('同事作品'),
    )
    await act(async () => colleagueTab?.click())
    await waitForText(container, '市场排班看板')
    expect(container.textContent).toContain('大促活动排班与值班日历')
    expect(container.textContent).toContain('静态页面')
    expect(container.textContent).toContain('市场部')

    const pageTwo = container.querySelector<HTMLElement>('.ant-pagination-item-2')
    expect(pageTwo).not.toBeNull()
    await act(async () => pageTwo?.click())
    await waitForText(container, '第二页作品')
    expect(getPortalColleagueApps).toHaveBeenCalledWith(expect.objectContaining({ limit: 24, offset: 24 }))

    // Search author name to display disambiguated author cards
    const search = container.querySelector<HTMLInputElement>(
      'input[aria-label="搜索作品名称或发布者姓名"]',
    )
    await act(async () => {
      if (!search) return
      Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set?.call(search, '张伟')
      search.dispatchEvent(new Event('input', { bubbles: true }))
    })
    await waitForText(container, '财务部')
    expect(getPortalColleagueApps).toHaveBeenCalledWith(expect.objectContaining({ query: '张伟', offset: 0 }))
    expect(container.textContent).toContain('2 个可见作品')
    expect(container.textContent).toContain('1 个可见作品')

    // Drill into 市场部 张伟's author view
    const marketAuthorCard = container.querySelector<HTMLButtonElement>(
      'button[aria-label="张伟 市场部"]',
    )
    expect(marketAuthorCard).not.toBeNull()
    await act(async () => marketAuthorCard?.click())
    await waitForText(container, '返回同事作品')
    expect(getPortalColleagueApps).toHaveBeenCalledWith(
      expect.objectContaining({ authorUserId: 'user-zhang-market' }),
    )

    // Open safe HTTPS hosted app in system browser
    const openSchedule = container.querySelector<HTMLButtonElement>(
      'button[aria-label="打开 市场排班看板"]',
    )
    await act(async () => openSchedule?.click())
    await vi.waitFor(() =>
      expect(openBrowserURL).toHaveBeenCalledWith('https://schedule-1a2b.apps.example.com/'),
    )

    authorRevoked = true
    await act(async () => {
      if (!search) return
      Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set?.call(search, '已撤回')
      search.dispatchEvent(new Event('input', { bubbles: true }))
    })
    await waitForText(container, '没有匹配的同事作品')
    expect(container.querySelector('.portal-author-banner-profile')).toBeNull()
    expect(container.textContent).not.toContain('市场排班看板')

    // Exit author view and switch kind filter to dynamic (unsafe URL must be rejected!)
    vi.mocked(openBrowserURL).mockClear()
    const backBtn = [...container.querySelectorAll('button')].find((btn) =>
      btn.textContent?.includes('返回同事作品'),
    )
    await act(async () => backBtn?.click())
    const dynamicBtn = [...container.querySelectorAll('button')].find(
      (btn) => btn.textContent === '交互工具',
    )
    await act(async () => dynamicBtn?.click())
    await waitForText(container, 'Unsafe Tool')

    const openUnsafe = container.querySelector<HTMLButtonElement>(
      'button[aria-label="打开 Unsafe Tool"]',
    )
    await act(async () => openUnsafe?.click())
    expect(openBrowserURL).not.toHaveBeenCalled()
  })

  it('renders colleague works empty guidance and error retry states', async () => {
    let failStaticOnce = true
    vi.mocked(getPortalColleagueApps).mockImplementation(async (params) => {
      if (params?.kind === 'static' && failStaticOnce) {
        failStaticOnce = false
        throw new Error('catalog down')
      }
      return { items: [], authors: [], myAppsCount: 0, total: 0 }
    })

    const container = await renderPortal()
    await waitForText(container, 'Soha Console')

    const colleagueTab = [...container.querySelectorAll<HTMLElement>('.ant-segmented-item')].find(
      (item) => item.textContent?.includes('同事作品'),
    )
    await act(async () => colleagueTab?.click())

    // Trigger filter so a new colleague query runs and hits the error mock, then retries to empty state
    const staticBtn = [...container.querySelectorAll('button')].find(
      (btn) => btn.textContent === '静态页面',
    )
    await act(async () => staticBtn?.click())
    await waitForText(container, '无法加载同事作品')

    const retryBtn = [...container.querySelectorAll('button')].find(
      (btn) => btn.textContent?.replace(/\s+/g, '') === '重试',
    )
    expect(retryBtn).toBeDefined()
    await act(async () => retryBtn?.click())
    await waitForText(container, '没有匹配的同事作品')

    const allBtn = [...container.querySelectorAll('button')].find(
      (btn) => btn.textContent?.replace(/\s+/g, '') === '全部',
    )
    expect(allBtn).toBeDefined()
    await act(async () => allBtn?.click())
    await waitForText(container, '暂无可见的同事作品')
    expect(container.textContent).toContain('soha host deploy')
  })
})
