import { beforeEach, describe, expect, it } from 'vitest'
import { useAppStore } from '@/store'

describe('app preferences persistence', () => {
  beforeEach(() => {
    localStorage.clear()
    useAppStore.setState({
      host: null,
      connection: null,
      session: null,
      bootstrap: null,
      themeMode: 'system',
      locale: 'zh_CN',
    })
  })

  it('persists preferences without account or token data', () => {
    useAppStore.getState().commitSession({
      accessToken: 'secret-access-token',
      user: {
        userId: 'user-1',
        userName: 'admin',
        email: 'admin@soha.local',
        roles: [],
        teams: [],
        projects: [],
        tags: [],
      },
    })
    useAppStore.getState().setThemeMode('dark')
    useAppStore.getState().setLocale('en_US')

    const persisted = localStorage.getItem('soha-app-preferences') || ''
    expect(persisted).toContain('dark')
    expect(persisted).toContain('en_US')
    expect(persisted).not.toContain('secret-access-token')
    expect(persisted).not.toContain('admin@soha.local')
  })

  it('falls back when persisted preferences contain unsupported values', async () => {
    localStorage.setItem(
      'soha-app-preferences',
      JSON.stringify({ state: { themeMode: 'sepia', locale: 'fr_FR' }, version: 1 }),
    )

    await useAppStore.persist.rehydrate()

    expect(useAppStore.getState().themeMode).toBe('system')
    expect(useAppStore.getState().locale).toBe('zh_CN')
  })

  it('restores supported preferences from the persisted state envelope', async () => {
    localStorage.setItem(
      'soha-app-preferences',
      JSON.stringify({ state: { themeMode: 'dark', locale: 'en_US' }, version: 1 }),
    )

    await useAppStore.persist.rehydrate()

    expect(useAppStore.getState().themeMode).toBe('dark')
    expect(useAppStore.getState().locale).toBe('en_US')
  })
})
