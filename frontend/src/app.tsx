import { Component, type ErrorInfo, type ReactNode, useCallback, useEffect, useRef, useState } from 'react'
import {
  AppstoreOutlined,
  GlobalOutlined,
  HomeOutlined,
  LinkOutlined,
  LogoutOutlined,
  ReloadOutlined,
  SafetyCertificateOutlined,
  SettingOutlined,
  UserOutlined,
} from '@ant-design/icons'
import { Alert, App, Avatar, Badge, Button, Result, Spin, Tooltip } from 'antd'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  MemoryRouter,
  Navigate,
  NavLink,
  Outlet,
  Route,
  Routes,
  useLocation,
  useNavigate,
} from 'react-router-dom'
import {
  ApiError,
  getBootstrap,
  logoutServer,
  registerEndpointDevice,
  restoreSession,
  setSessionListener,
} from '@/api'
import { applyBranding } from '@/branding'
import { useText } from '@/i18n'
import {
  checkServer,
  clearHostSession,
  getHostState,
  getUpdateStatus,
  installUpdate,
  openBrowserURL,
} from '@/native/host'
import {
  ConnectionPage,
  HomePage,
  LoginPage,
  NetworkPage,
  ProfilePage,
  ProxyPage,
  SettingsPage,
  SoftwarePage,
  VPNPage,
  connectionMessage,
} from '@/pages'
import { PortalApplicationPage, PortalPage } from '@/portal-pages'
import { useAppStore } from '@/store'
import { avatarURL, displayName } from '@/types'

export function DesktopApp({ initialEntries }: { initialEntries?: string[] } = {}) {
  const text = useText()
  return (
    <ErrorBoundary
      reloadLabel={text.reload}
      subTitle={text.renderFailedHelp}
      title={text.renderFailed}
    >
      <MemoryRouter initialEntries={initialEntries}>
        <SessionBridge />
        <Routes>
          <Route path="/" element={<StartupPage />} />
          <Route path="/connect" element={<ConnectionPage />} />
          <Route path="/login" element={<LoginPage />} />
          <Route element={<AuthGuard />}>
            <Route element={<DesktopShell />}>
              <Route path="/home" element={<HomePage />} />
              <Route path="/portal" element={<PortalPage />} />
              <Route path="/portal/applications/:applicationId" element={<PortalApplicationPage />} />
              <Route path="/network" element={<NetworkPage />} />
              <Route path="/vpn" element={<VPNPage />} />
              <Route path="/proxy" element={<ProxyPage />} />
              <Route path="/profile" element={<ProfilePage />} />
              <Route path="/software" element={<SoftwarePage />} />
              <Route path="/settings" element={<SettingsPage />} />
            </Route>
          </Route>
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </MemoryRouter>
    </ErrorBoundary>
  )
}

function StartupPage() {
  const navigate = useNavigate()
  const [label, setLabel] = useState<'checking' | 'restoring'>('checking')
  const [failed, setFailed] = useState(false)
  const [attempt, setAttempt] = useState(0)
  const setHost = useAppStore((state) => state.setHost)
  const setConnection = useAppStore((state) => state.setConnection)
  const commitSession = useAppStore((state) => state.commitSession)

  useEffect(() => {
    let active = true
    const start = async () => {
      let serverOnline = false
      setFailed(false)
      setLabel('checking')
      try {
        const host = await getHostState()
        if (!active) return
        setHost(host)
        setConnection({ status: 'checking', serverUrl: host.serverUrl })
        const checked = await checkServer(host.serverUrl)
        if (!active) return
        const connection = host.configurationSource === 'default' && checked.status === 'offline'
          ? { ...checked, status: 'unconfigured' as const, code: 'server_not_configured' }
          : checked
        setConnection(connection)
        if (connection.status !== 'online') {
          navigate('/connect', { replace: true })
          return
        }
        serverOnline = true
        setLabel('restoring')
        const session = await restoreSession()
        if (!active) return
        if (!session) {
          navigate('/login', { replace: true })
          return
        }
        const bootstrap = await getBootstrap()
        if (!active) return
        commitSession(session, bootstrap)
        applyBranding(bootstrap.branding)
        navigate('/home', { replace: true })
      } catch (error) {
        if (!active) return
        if (error instanceof ApiError && (error.status === 401 || error.status === 403)) {
          navigate('/login', { replace: true })
          return
        }
        if (serverOnline) {
          setFailed(true)
          return
        }
        navigate('/connect', { replace: true })
      }
    }
    void start()
    return () => {
      active = false
    }
  }, [attempt, commitSession, navigate, setConnection, setHost])

  const text = useText()
  if (failed) {
    return (
      <Result
        extra={(
          <Button
            icon={<ReloadOutlined />}
            onClick={() => setAttempt((current) => current + 1)}
            type="primary"
          >
            {text.retry}
          </Button>
        )}
        status="warning"
        subTitle={text.startupFailedHelp}
        title={text.startupFailed}
      />
    )
  }
  return (
    <div className="startup-state" role="status">
      <Spin size="large" />
      <span>{text[label]}</span>
    </div>
  )
}

function SessionBridge() {
  const { message } = App.useApp()
  const text = useText()
  const queryClient = useQueryClient()
  const commitSession = useAppStore((state) => state.commitSession)
  const clearSession = useAppStore((state) => state.clearSession)
  useEffect(() => {
    setSessionListener((session) => {
      if (session) {
        commitSession(session)
        return
      }
      clearSession()
      queryClient.clear()
      message.warning(text.sessionExpired)
    })
    return () => setSessionListener(null)
  }, [clearSession, commitSession, message, queryClient, text.sessionExpired])
  return null
}

function AuthGuard() {
  const session = useAppStore((state) => state.session)
  return session ? <Outlet /> : <Navigate to="/login" replace />
}

function DesktopShell() {
  const navigate = useNavigate()
  const location = useLocation()
  const queryClient = useQueryClient()
  const { message } = App.useApp()
  const text = useText()
  const host = useAppStore((state) => state.host)
  const connection = useAppStore((state) => state.connection)
  const session = useAppStore((state) => state.session)
  const bootstrap = useAppStore((state) => state.bootstrap)
  const setConnection = useAppStore((state) => state.setConnection)
  const clearSession = useAppStore((state) => state.clearSession)
  const [checkingConnection, setCheckingConnection] = useState(false)
  const [dismissedUpdateVersion, setDismissedUpdateVersion] = useState('')
  const connectionCheckPending = useRef(false)
  const workspace = useRef<HTMLElement>(null)
  const user = bootstrap?.currentUser || session?.user
  const name = displayName(user) || text.account
  const updateQuery = useQuery({
    queryKey: ['update-status'],
    queryFn: getUpdateStatus,
    enabled: Boolean(host?.app.updateSupported),
    refetchInterval: 60_000,
    retry: false,
  })
  const deviceRegistration = useQuery({
    queryKey: ['endpoint-device-registration', host?.serverUrl, host?.app.deviceId, session?.user.userId],
    queryFn: async () => {
      const deviceId = host!.app.deviceId!
      const hostname = host!.app.hostname || ''
      await registerEndpointDevice(deviceId, {
        name: hostname || `${host!.app.name} ${host!.app.platform}`,
        ...(hostname ? { hostname } : {}),
        platform: host!.app.platform,
        ...(host!.app.deviceType ? { deviceType: host!.app.deviceType } : {}),
        ...(host!.app.reportedFacts ? { reportedFacts: host!.app.reportedFacts } : {}),
      })
      return deviceId
    },
    enabled: Boolean(host?.app.deviceId && session?.user.userId),
    staleTime: Infinity,
    retry: 1,
  })
  const installMutation = useMutation({
    mutationFn: installUpdate,
    onSuccess: (status) => queryClient.setQueryData(['update-status'], status),
    onError: (error) => message.error(error instanceof Error ? error.message : text.updateFailed),
  })
  const availableUpdate = updateQuery.data?.state === 'available' ? updateQuery.data : undefined

  const refreshConnection = useCallback(async () => {
    if (!host?.serverUrl || connectionCheckPending.current) return
    connectionCheckPending.current = true
    setCheckingConnection(true)
    try {
      setConnection(await checkServer(host.serverUrl))
    } catch {
      setConnection({ status: 'offline', serverUrl: host.serverUrl, code: 'host_unavailable' })
    } finally {
      connectionCheckPending.current = false
      setCheckingConnection(false)
    }
  }, [host?.serverUrl, setConnection])

  useEffect(() => {
    const refreshWhenVisible = () => {
      if (document.visibilityState === 'visible') void refreshConnection()
    }
    document.addEventListener('visibilitychange', refreshWhenVisible)
    return () => document.removeEventListener('visibilitychange', refreshWhenVisible)
  }, [refreshConnection])

  useEffect(() => {
    workspace.current?.focus()
  }, [location.pathname])

  const logout = async () => {
    await queryClient.cancelQueries()
    let remoteFailed = false
    try {
      await logoutServer()
    } catch {
      remoteFailed = true
    }
    try {
      await clearHostSession()
    } catch {
      remoteFailed = true
    }
    clearSession()
    queryClient.clear()
    if (remoteFailed) message.warning(text.signOutFailed)
    navigate('/login', { replace: true })
  }

  const navigation = [
    { path: '/home', label: text.home, icon: <HomeOutlined /> },
    { path: '/portal', label: text.portal, icon: <AppstoreOutlined /> },
    { path: '/software', label: text.software, icon: <AppstoreOutlined /> },
    { path: '/network', label: text.network, icon: <GlobalOutlined /> },
    { path: '/vpn', label: text.vpn, icon: <SafetyCertificateOutlined /> },
    { path: '/proxy', label: text.proxy, icon: <LinkOutlined /> },
    { path: '/profile', label: text.profile, icon: <UserOutlined /> },
    {
      path: '/settings',
      label: text.settings,
      icon: <Badge className="nav-update-badge" dot={Boolean(availableUpdate)}><SettingOutlined /></Badge>,
    },
  ]
  const connectionCopy = connection
    ? connectionMessage(connection, text)
    : { title: text.checking, description: text.offlineHelp }
  const connectionClass = checkingConnection ? 'checking' : (connection?.status || 'checking')

  return (
    <div className="desktop-shell" data-platform={host?.app.platform}>
      <NavLink
        className="skip-link"
        onClick={(event) => {
          event.preventDefault()
          workspace.current?.focus()
        }}
        to="#main-content"
      >
        {text.skipToContent}
      </NavLink>
      <aside className="sidebar">
        <div aria-hidden="true" className="sidebar-drag-region" />
        <nav aria-label={text.desktopNavigation}>
          {navigation.map((item) => (
            <NavLink
              className={({ isActive }) => `nav-item${isActive ? ' active' : ''}`}
              key={item.path}
              to={item.path}
            >
              {item.icon}
              <span>{item.label}</span>
            </NavLink>
          ))}
        </nav>
        <div className="sidebar-footer">
          <div className="user-card">
            <button className="user-summary" onClick={() => navigate('/profile')} type="button">
              <Avatar icon={<UserOutlined />} size={34} src={avatarURL(user)} />
              <span>
                <strong>{name}</strong>
                <small>{user?.email || ''}</small>
              </span>
            </button>
            <Tooltip placement="right" title={text.logout}>
              <Button
                aria-label={text.logout}
                className="user-logout"
                danger
                icon={<LogoutOutlined />}
                onClick={() => void logout()}
                title={text.logout}
                type="text"
              />
            </Tooltip>
          </div>
        </div>
      </aside>
      <main
        aria-label={text.mainContent}
        className="workspace"
        id="main-content"
        ref={workspace}
        tabIndex={-1}
      >
        <header className="titlebar">
          <div className="connection-controls">
            <span
              aria-live="polite"
              className={`connection-indicator ${connectionClass}`}
              role="status"
              title={connectionCopy.description}
            >
              <i /> {checkingConnection ? text.checking : connectionCopy.title}
            </span>
            {connection?.status !== 'online' ? (
              <Button
                aria-label={text.retry}
                icon={<ReloadOutlined />}
                loading={checkingConnection}
                onClick={() => void refreshConnection()}
                size="small"
                title={text.retry}
                type="text"
              />
            ) : null}
          </div>
          <span className="server-label" title={host?.serverUrl}>{host?.serverUrl}</span>
        </header>
        {availableUpdate?.availableVersion && dismissedUpdateVersion !== availableUpdate.availableVersion ? (
          <Alert
            action={availableUpdate.installMode !== 'disabled' ? (
              <Button
                loading={installMutation.isPending}
                onClick={() => {
                  if (availableUpdate.installMode === 'external') {
                    if (availableUpdate.releaseURL) {
                      void openBrowserURL(availableUpdate.releaseURL).catch((error) => {
                        message.error(error instanceof Error ? error.message : text.updateFailed)
                      })
                    }
                    return
                  }
                  if (availableUpdate.installMode === 'self') installMutation.mutate()
                }}
                size="small"
                type="primary"
              >
                {availableUpdate.installMode === 'external' ? text.openRelease : text.installUpdate}
              </Button>
            ) : undefined}
            className="update-banner"
            closable={{
              closeIcon: true,
              onClose: () => setDismissedUpdateVersion(availableUpdate.availableVersion || ''),
            }}
            showIcon
            title={`${text.updateAvailable} ${availableUpdate.availableVersion}`}
            type="info"
          />
        ) : null}
        <div className="workspace-scroll">
          {deviceRegistration.isError ? (
            <Alert className="endpoint-registration-alert" showIcon title={text.networkDeviceRegistrationFailed} type="warning" />
          ) : null}
          <Outlet />
        </div>
      </main>
    </div>
  )
}

class ErrorBoundary extends Component<{
  children: ReactNode
  reloadLabel: string
  subTitle: string
  title: string
}, { failed: boolean }> {
  state = { failed: false }

  static getDerivedStateFromError() {
    return { failed: true }
  }

  componentDidCatch(_error: Error, _info: ErrorInfo) {}

  render() {
    if (!this.state.failed) return this.props.children
    return (
      <Result
        extra={<Button onClick={() => window.location.reload()}>{this.props.reloadLabel}</Button>}
        status="error"
        subTitle={this.props.subTitle}
        title={this.props.title}
      />
    )
  }
}
