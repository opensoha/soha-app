/** @vitest-environment jsdom */

import { act } from 'react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { createRoot, type Root } from 'react-dom/client'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { App as AntApp } from 'antd'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { PortalApplicationPage, PortalPage } from '@/portal-pages'
import {
  getPortalApplication,
  getPortalBootstrap,
  launchPortalApplication,
  setPortalFavorite,
} from '@/api'
import { openBrowserURL } from '@/native/host'
import { useAppStore } from '@/store'

vi.mock('@/api', () => ({
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
  applications: [application],
  favorites: [],
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

  it('persists favorites through the Server', async () => {
    const container = await renderPortal()
    await waitForText(container, 'Soha Console')
    const favorite = container.querySelector<HTMLButtonElement>('button[aria-label="收藏 Soha Console"]')

    await act(async () => favorite?.click())

    expect(setPortalFavorite).toHaveBeenCalledWith('app-1', true)
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
