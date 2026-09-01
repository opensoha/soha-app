import type {
  AuthProvider as ContractAuthProvider,
  IdentityApplication as ContractIdentityApplication,
  LoginOptions as ContractLoginOptions,
  Principal as ContractPrincipal,
} from '@opensoha/contracts/gen/ts/sohaapi'

export type AuthProvider = ContractAuthProvider
export type LoginOptions = ContractLoginOptions
export type Principal = ContractPrincipal

// ponytail: remove this compatibility layer when @opensoha/contracts >= 0.1.16 is published.
type PortalProviderType = 'link' | 'oidc' | 'proxy' | 'saml'

export type IdentityApplication = Omit<ContractIdentityApplication, 'status'> & {
  iconUrl?: string
  category?: string
  tags?: string[]
  providerId?: string
  providerType?: PortalProviderType
  portalVisible?: boolean
  featured?: boolean
  sortOrder?: number
  status: 'active' | 'draft' | 'enabled' | 'disabled' | 'maintenance'
  metadata?: Record<string, unknown>
  favorite?: boolean
  lastLaunchedAt?: string
  createdBy?: string
  updatedBy?: string
}

export interface IdentityApplicationLaunch {
  id: string
  applicationId: string
  applicationName?: string
  userId: string
  providerId?: string
  providerType: PortalProviderType
  result: string
  reason?: string
  launchUrl?: string
  sourceIp?: string
  userAgent?: string
  createdAt: string
}

export interface PortalBootstrap {
  principal: Principal
  applications: IdentityApplication[]
  favorites: IdentityApplication[]
  recent: IdentityApplicationLaunch[]
  categories: string[]
  security: {
    principal: Principal
    mfaEnabled: boolean
    linkedSources: string[]
    activeSession: number
    recentLoginAt?: string
  }
}

export interface PortalLaunchDecision {
  application: IdentityApplication
  launchUrl: string
  providerType: PortalProviderType
  decision: 'allow'
  handoffExpiresAt?: string
}

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
  updateState?: string
}

export interface HostState {
  serverUrl: string
  configurationSource: 'default' | 'saved' | 'environment' | 'runtime'
  managedByEnvironment: boolean
  app: AppInfo
}

export interface SoftwarePackage {
  id: string
  name: string
  description?: string
  publisher: string
  category?: string
  version: string
  size: number
}

export type SoftwareTaskState =
  | 'queued'
  | 'downloading'
  | 'verifying'
  | 'opening'
  | 'completed'
  | 'failed'

export interface SoftwareInstallTask {
  id: string
  softwareId: string
  name: string
  state: SoftwareTaskState
  progress: number
  message: string
}

export interface SoftwareListResponse {
  items: SoftwarePackage[]
}

export interface SoftwareTaskResponse {
  task: SoftwareInstallTask
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
