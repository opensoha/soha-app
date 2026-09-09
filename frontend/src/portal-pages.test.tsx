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
  launchPortalApplication,
  setPortalFavorite,
} from '@/api'
import { openBrowserURL } from '@/native/host'
import { useAppStore } from '@/store'

vi.mock('@/api', () => ({
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
  launchPortalApplication: vi.fn(),
  setPortalFavorite: vi.fn(),
}))

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
    const open = [...container.querySelectorAll('button')].find((button) =>
      button.textContent?.includes('打开'),
    )

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
    const open = [...container.querySelectorAll('button')].find((button) =>
      button.textContent?.includes('打开'),
    )

    await act(async () => open?.click())

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
})
