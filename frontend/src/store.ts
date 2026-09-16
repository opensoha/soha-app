import { create } from 'zustand'
import { persist } from 'zustand/middleware'
import { setAccessToken } from '@/api'
import type { Bootstrap, ConnectionCheck, HostState, Principal, Session, UserProfile } from '@/types'

export type ThemeMode = 'system' | 'light' | 'dark'
export type LocaleCode = 'zh_CN' | 'en_US'
export type PortalCardSize = 'standard' | 'compact'

export interface NetworkConnectionPreferences {
  selectedWifiKey: string
  wifiAutoConnect: boolean
  wiredAutoConnect: boolean
}

const defaultNetworkConnectionPreferences: NetworkConnectionPreferences = {
  selectedWifiKey: '',
  wifiAutoConnect: false,
  wiredAutoConnect: false,
}

export interface VPNRecoveryPlan { profileId: string; selection: string; max: number; cooldown: number; failures: number; attempts: number; nextAt: number }

interface AppState {
 vpnRecovery: VPNRecoveryPlan | null
 setVPNRecovery: (plan: VPNRecoveryPlan | null) => void
  host: HostState | null
  connection: ConnectionCheck | null
  session: Session | null
  bootstrap: Bootstrap | null
  themeMode: ThemeMode
  locale: LocaleCode
  portalCardSize: PortalCardSize
  networkConnection: NetworkConnectionPreferences
  setHost: (host: HostState) => void
  setConnection: (connection: ConnectionCheck) => void
  commitSession: (session: Session, bootstrap?: Bootstrap | null) => void
  setBootstrap: (bootstrap: Bootstrap) => void
  updateProfileSummary: (profile: UserProfile) => void
  clearSession: () => void
  setThemeMode: (themeMode: ThemeMode) => void
  setLocale: (locale: LocaleCode) => void
  setPortalCardSize: (portalCardSize: PortalCardSize) => void
  setNetworkConnection: (preferences: Partial<NetworkConnectionPreferences>) => void
}

export const useAppStore = create<AppState>()(
  persist(
    (set) => ({
      host: null,
      connection: null,
      session: null,
      bootstrap: null,
      themeMode: 'system',
      locale: 'zh_CN',
      portalCardSize: 'standard',
      networkConnection: defaultNetworkConnectionPreferences,
 vpnRecovery: null,
 setVPNRecovery: (vpnRecovery) => set({vpnRecovery}),
      setHost: (host) => set({ host }),
      setConnection: (connection) => set({ connection }),
      commitSession: (session, bootstrap = null) => {
        setAccessToken(session.accessToken)
        set({ session, bootstrap })
      },
      setBootstrap: (bootstrap) => set({ bootstrap }),
      updateProfileSummary: (profile) =>
        set((state) => {
          if (!state.session) return state
          const user = patchPrincipal(state.session.user, profile)
          const bootstrap = state.bootstrap
            ? {
                ...state.bootstrap,
                user: patchPrincipal(state.bootstrap.user, profile),
                currentUser: patchPrincipal(state.bootstrap.currentUser, profile),
              }
            : null
          return { session: { ...state.session, user }, bootstrap }
        }),
      clearSession: () => {
        setAccessToken(null)
        set({ session: null, bootstrap: null, vpnRecovery: null, networkConnection: defaultNetworkConnectionPreferences })
      },
      setThemeMode: (themeMode) => set({ themeMode }),
      setLocale: (locale) => set({ locale }),
      setPortalCardSize: (portalCardSize) => set({ portalCardSize }),
      setNetworkConnection: (preferences) =>
        set((state) => ({ networkConnection: { ...state.networkConnection, ...preferences } })),
    }),
    {
      name: 'soha-app-preferences',
      version: 1,
      partialize: (state) => ({
        themeMode: state.themeMode,
        locale: state.locale,
        portalCardSize: state.portalCardSize,
        networkConnection: state.networkConnection,
      }),
      merge: (persisted, current) => {
        const preferences =
          typeof persisted === 'object' && persisted !== null ? (persisted as Partial<AppState>) : {}
        return {
          ...current,
          themeMode:
            preferences.themeMode === 'light' || preferences.themeMode === 'dark'
              ? preferences.themeMode
              : 'system',
          locale: preferences.locale === 'en_US' ? 'en_US' : 'zh_CN',
          portalCardSize: preferences.portalCardSize === 'compact' ? 'compact' : 'standard',
          networkConnection: normalizeNetworkConnectionPreferences(preferences.networkConnection),
        }
      },
    },
  ),
)

function normalizeNetworkConnectionPreferences(value: unknown): NetworkConnectionPreferences {
  if (typeof value !== 'object' || value === null) return defaultNetworkConnectionPreferences
  const preferences = value as Partial<NetworkConnectionPreferences>
  return {
    selectedWifiKey: typeof preferences.selectedWifiKey === 'string' && preferences.selectedWifiKey.length <= 512
      ? preferences.selectedWifiKey
      : '',
    wifiAutoConnect: preferences.wifiAutoConnect === true,
    wiredAutoConnect: preferences.wiredAutoConnect === true,
  }
}

function patchPrincipal(user: Principal, profile: UserProfile): Principal {
  return {
    ...user,
    userName: profile.username,
    email: profile.email,
    displayName: profile.displayName,
    phone: profile.phone,
    avatarUrl: profile.avatarUrl,
  }
}
