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

export type EndpointDeviceType = 'desktop' | 'laptop' | 'server' | 'mobile' | 'tablet' | 'virtual' | 'unknown'

export interface EndpointNetworkInterface {
  name: string
  displayName?: string
  kind: 'physical' | 'virtual' | 'loopback' | 'unknown'
  status: 'up' | 'down' | 'unknown'
  macAddress?: string
  ipv4Addresses: string[]
  ipv6Addresses: string[]
  dnsServers?: string[]
}

export interface EndpointDeviceReportedFacts {
  osName?: string
  osVersion?: string
  osBuild?: string
  architecture: string
  manufacturer?: string
  model?: string
  serialNumber?: string
  agentVersion: string
  collectedAt: string
  networkInterfaces: EndpointNetworkInterface[]
}

export interface EndpointDeviceRegistrationInput {
  name: string
  hostname?: string
  platform: string
  deviceType?: EndpointDeviceType
  reportedFacts?: EndpointDeviceReportedFacts
}

export interface AppInfo {
  name: string
  version: string
  platform: string
  arch: string
  deviceId?: string
  hostname?: string
  deviceType?: EndpointDeviceType
  reportedFacts?: EndpointDeviceReportedFacts
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

export type NetworkAccessMode = 'internal_ztna' | 'external_vpn' | 'external_vpn_ztna' | 'external_direct_ztna'
export type NetworkAccessGrantMode = Exclude<NetworkAccessMode, 'external_vpn'>

export interface NetworkAccessGrantInput {
  deviceId: string
  siteId: string
  networkSpaceId: string
  mode: NetworkAccessGrantMode
  resourceIds: string[]
  ttlSeconds?: number
}

export interface NetworkAccessGrantSecret {
  grant: { id: string }
  token: string
}

export type NetworkAccessMedium = 'wifi' | 'wired'

export interface NetworkConnectionOption {
  siteId: string
  siteName: string
  accessMedium: NetworkAccessMedium
  ssid?: string
  authentication: 'radius_802_1x' // gitleaks:allow -- public protocol enum
  accessProfile: 'onboarding' | 'full' | 'restricted' | 'quarantine' | 'deny'
  policyVersion: number
}

export interface NetworkLinkStatus {
  connected: boolean
  medium?: NetworkAccessMedium
  interfaceName?: string
  ipAddress?: string
  gateway?: string
  dnsServers: string[]
}

export type NetworkConnectInput = { intentId: string; intentToken: string; requestId: string } | LegacyNetworkConnectInput

export interface LegacyNetworkConnectInput {
	siteId: string
	networkSpaceId: string
	gatewayId?: string
	mode: NetworkAccessMode
  resourceIds: string[]
  accessGrantId?: string
  accessGrantToken?: string
}

export interface NetworkServiceStatus {
  profileId?: string
  profileRevision?: number
  selection?: 'auto' | 'manual'
  selectionReason?: string
  decisionId?: string
  phase?: string
  probeResults?: { gatewayId: string; sentCount: number; rttSamplesMs: number[] }[]
  probeMeasuredAt?: string
  failoverOnDisconnect?: boolean
  retryCooldownSeconds?: number
  maxAttempts?: number
  connectedAt?: string
  tunnelIP?: string

  state: 'disconnected' | 'connecting' | 'connected' | 'degraded'
  runtimeId: string
  deviceId: string
  siteId?: string
  networkSpaceId?: string
  mode?: NetworkAccessMode
  resourceIds?: string[]
  sessionId?: string
  gatewayId?: string
  configurationVersion: number
  policyVersion: number
  validUntil?: string
  mihomoMode?: 'managed_follow' | 'app_subscription'
  mihomoProfileId?: string
  mihomoProfileRevision?: number
  uptimeSeconds: number
  diagnostic?: string
}

export interface MihomoAppInput {
	subscriptionUrl?: string
	selectedProxy?: string
}

export interface MihomoAppStatus {
	mode: 'app_subscription'
	profileId: string
	profileRevision: number
	configured: boolean
	selectedProxy?: string
	proxies: string[]
}

export interface UpdateStatus {
  supported: boolean
  installMode: 'self' | 'external' | 'disabled'
  state: 'unconfigured' | 'idle' | 'checking' | 'up-to-date' | 'available' | 'downloading' | 'verifying' | 'installing' | 'ready' | 'error'
  currentVersion: string
  availableVersion?: string
  downloadMode?: 'delta' | 'full'
  lastCheckedAt?: string
  releaseURL?: string
  errorCode?: string
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
