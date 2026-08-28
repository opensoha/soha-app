import { Component, type ErrorInfo, type ReactNode, useCallback, useEffect, useRef, useState } from 'react'
import {
  HomeOutlined,
  LogoutOutlined,
  ReloadOutlined,
  SettingOutlined,
  UserOutlined,
} from '@ant-design/icons'
import { App, Avatar, Button, Result, Spin } from 'antd'
import { useQueryClient } from '@tanstack/react-query'
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
  restoreSession,
  setSessionListener,
} from '@/api'
import { applyBranding } from '@/branding'
import { useText } from '@/i18n'
import { checkServer, clearHostSession, getHostState } from '@/native/host'
import {
  ConnectionPage,
  HomePage,
  LoginPage,
  ProfilePage,
  SettingsPage,
  connectionMessage,
} from '@/pages'
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
              <Route path="/profile" element={<ProfilePage />} />
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
  const connectionCheckPending = useRef(false)
  const workspace = useRef<HTMLElement>(null)
  const user = bootstrap?.currentUser || session?.user
  const name = displayName(user) || text.account

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
    { path: '/profile', label: text.profile, icon: <UserOutlined /> },
    { path: '/settings', label: text.settings, icon: <SettingOutlined /> },
  ]
  const connectionCopy = connection
    ? connectionMessage(connection, text)
    : { title: text.checking, description: text.offlineHelp }
  const connectionClass = checkingConnection ? 'checking' : (connection?.status || 'checking')

  return (
    <div className="desktop-shell">
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
        <div className="brand">
          <span className="brand-mark">S</span>
          <span>
            <strong>{bootstrap?.branding.sidebarTitle || text.appName}</strong>
            <small>Desktop</small>
          </span>
        </div>
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
          <button className="user-summary" onClick={() => navigate('/profile')} type="button">
            <Avatar icon={<UserOutlined />} size={34} src={avatarURL(user)} />
            <span>
              <strong>{name}</strong>
              <small>{user?.email || ''}</small>
            </span>
          </button>
          <Button block icon={<LogoutOutlined />} onClick={() => void logout()} type="text">
            {text.logout}
          </Button>
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
        <div className="workspace-scroll">
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
