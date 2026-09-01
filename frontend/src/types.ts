import type {
  AuthProvider as ContractAuthProvider,
  IdentityApplication as ContractIdentityApplication,
  IdentityApplicationLaunch as ContractIdentityApplicationLaunch,
  LoginOptions as ContractLoginOptions,
  PortalBootstrap as ContractPortalBootstrap,
  PortalLaunchDecision as ContractPortalLaunchDecision,
  Principal as ContractPrincipal,
} from '@opensoha/contracts/gen/ts/sohaapi'

export type AuthProvider = ContractAuthProvider
export type LoginOptions = ContractLoginOptions
export type Principal = ContractPrincipal
export type IdentityApplication = ContractIdentityApplication
export type IdentityApplicationLaunch = ContractIdentityApplicationLaunch
export type PortalBootstrap = ContractPortalBootstrap
export type PortalLaunchDecision = ContractPortalLaunchDecision

export interface Session {
  accessToken: string
  user: Principal
}

export interface Branding {
  appTitle?: string
  sidebarTitle?: string
  slogan?: string
  loginLogoUrl?: string
  expandedLogoUrl?: string
  collapsedLogoUrl?: string
  faviconUrl?: string
}

export interface PermissionSnapshot {
  permissionKeys: string[]
}

export interface Bootstrap {
  user: Principal
  currentUser: Principal
  permissionSnapshot: PermissionSnapshot
  branding: Branding
}

export interface LinkedIdentity {
  id?: string
  providerType: string
  providerId?: string
  displayName?: string
  email?: string
  lastLoginAt?: string
}

export interface UserProfile {
  userId: string
  username: string
  displayName: string
  email: string
  phone?: string
  avatarUrl?: string
  avatarFit?: string
  status: string
  roles: string[]
  teams: string[]
  projects: string[]
  tags: string[]
  identities: LinkedIdentity[]
  lastLoginAt?: string
}

export interface ProfileUpdate {
  displayName: string
  email: string
  phone?: string
  avatarUrl?: string
  avatarFit?: string
}

export interface Announcement {
  id: string
  title: string
  summary: string
  level: string
  publishedAt?: string | null
  isRead: boolean
}

export interface AnnouncementInbox {
  items: Announcement[]
  unreadCount: number
}

export type ConnectionStatus =
  | 'unconfigured'
  | 'checking'
  | 'online'
  | 'not_ready'
  | 'offline'
  | 'tls_error'
  | 'incompatible'

export interface ConnectionCheck {
  status: ConnectionStatus
  serverUrl: string
  code?: string
}

export interface AppInfo {
  name: string
  version: string
  platform: string
  arch: string
  logDirectory: string
  updateSupported: boolean
}

export interface HostState {
  serverUrl: string
  configurationSource: 'default' | 'saved' | 'environment' | 'runtime'
  managedByEnvironment: boolean
  app: AppInfo
}

export function displayName(user: Principal | null | undefined): string {
  if (!user) return ''
  const preferred = user.displayName
  return typeof preferred === 'string' && preferred.trim() ? preferred : user.userName || user.email
}

export function avatarURL(user: Principal | null | undefined): string | undefined {
  const value = user?.avatarUrl
  return typeof value === 'string' && value ? value : undefined
}
