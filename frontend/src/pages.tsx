import { useEffect, useRef, useState, type ReactNode } from 'react'
import {
  CheckOutlined,
  CloudServerOutlined,
  FolderOpenOutlined,
  LockOutlined,
  ReloadOutlined,
  SafetyCertificateOutlined,
  UserOutlined,
} from '@ant-design/icons'
import {
  Alert,
  App,
  Avatar,
  Button,
  Descriptions,
  Empty,
  Form,
  Input,
  Modal,
  Result,
  Segmented,
  Select,
  Skeleton,
  Slider,
  Spin,
  Tag,
} from 'antd'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import {
  ApiError,
  changePassword,
  getAnnouncementInbox,
  getAuthProviders,
  getBootstrap,
  getLoginOptions,
  getProfile,
  loginWithProvider,
  loginWithPassword,
  markAnnouncementRead,
  updateProfile,
} from '@/api'
import { applyBranding } from '@/branding'
import { type Text, useText } from '@/i18n'
import {
  HostError,
  activateServerSwitch,
  checkServer,
  getHostState,
  openLogDirectory,
  prepareServerSwitch,
} from '@/native/host'
import { type LocaleCode, type ThemeMode, useAppStore } from '@/store'
import {
  avatarURL,
  displayName,
  type AuthProvider,
  type ConnectionCheck,
  type HostState,
  type ProfileUpdate,
} from '@/types'

export function ConnectionPage() {
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const text = useText()
  const [form] = Form.useForm<{ serverUrl: string }>()
  const [pending, setPending] = useState(false)
  const [localError, setLocalError] = useState<string | null>(null)
  const host = useAppStore((state) => state.host)
  const connection = useAppStore((state) => state.connection)
  const session = useAppStore((state) => state.session)
  const setHost = useAppStore((state) => state.setHost)
  const setConnection = useAppStore((state) => state.setConnection)
  const clearSession = useAppStore((state) => state.clearSession)

  useEffect(() => {
    if (host) {
      form.setFieldValue('serverUrl', host.serverUrl)
      return
    }
    void getHostState()
      .then((state) => {
        setHost(state)
        form.setFieldValue('serverUrl', state.serverUrl)
      })
      .catch(() => setLocalError(text.offlineHelp))
  }, [form, host, setHost, text.offlineHelp])

  const connect = async ({ serverUrl }: { serverUrl: string }) => {
    let preparedConnection: ConnectionCheck | null = null
    setPending(true)
    setLocalError(null)
    setConnection({ status: 'checking', serverUrl })
    try {
      const checked = await checkServer(serverUrl)
      setConnection(checked)
      if (checked.status !== 'online') return
      if (host && checked.serverUrl === host.serverUrl) {
        navigate('/', { replace: true })
        return
      }
      await queryClient.cancelQueries()
      const prepared = await prepareServerSwitch(checked.serverUrl, session?.accessToken)
      preparedConnection = prepared.connection
      clearSession()
      queryClient.clear()
      const nextHost = await activateServerSwitch(prepared.activationToken)
      setHost(nextHost)
      setConnection(prepared.connection)
      navigate('/login', { replace: true })
    } catch (error) {
      const activated = preparedConnection
        ? await recoverHostAfterSwitch(preparedConnection, setHost, setConnection).catch(() => false)
        : false
      if (activated) {
        navigate('/login', { replace: true })
      } else {
        setLocalError(readableError(error, text))
      }
    } finally {
      setPending(false)
    }
  }

  const connectionCopy = connection && connection.status !== 'online' && connection.status !== 'checking'
    ? connectionMessage(connection, text)
    : null

  return (
    <div className="connection-screen">
      <header className="connection-header">
        <img alt="" aria-hidden="true" className="brand-mark" src="/logo.svg" />
        <strong>{text.appName}</strong>
      </header>
      <main className="connection-main">
        <section className="connection-panel">
          <CloudServerOutlined className="connection-icon" />
          <h1>{text.connectTitle}</h1>
          <p>{text.connectDescription}</p>
          {connectionCopy ? (
            <Alert description={connectionCopy.description} showIcon title={connectionCopy.title} type="warning" />
          ) : null}
          {localError ? <Alert showIcon title={localError} type="error" /> : null}
          <Form form={form} layout="vertical" onFinish={connect} requiredMark={false}>
            <Form.Item
              label={text.serverAddress}
              name="serverUrl"
              rules={[{ required: true, message: text.invalidAddress }]}
            >
              <Input
                autoCapitalize="none"
                autoComplete="url"
                autoCorrect="off"
                disabled={host?.managedByEnvironment}
                placeholder="https://soha.example.com"
                spellCheck={false}
              />
            </Form.Item>
            {host?.managedByEnvironment ? <p className="field-note">{text.managedAddress}</p> : null}
            <Button block htmlType="submit" loading={pending} type="primary">
              {connection && connection.status !== 'unconfigured' ? text.retry : text.connect}
            </Button>
          </Form>
        </section>
      </main>
    </div>
  )
}

export function LoginPage() {
  const navigate = useNavigate()
  const { message } = App.useApp()
  const text = useText()
  const [pending, setPending] = useState(false)
  const [sliderValue, setSliderValue] = useState(0)
  const [sliderVerified, setSliderVerified] = useState(false)
  const [providerPending, setProviderPending] = useState<AuthProvider | null>(null)
  const authAttemptPending = useRef(false)
  const providerController = useRef<AbortController | null>(null)
  const host = useAppStore((state) => state.host)
  const commitSession = useAppStore((state) => state.commitSession)
  const optionsQuery = useQuery({ queryKey: ['auth', 'login-options'], queryFn: getLoginOptions })
  const providersQuery = useQuery({ queryKey: ['auth', 'providers'], queryFn: getAuthProviders })
  const options = optionsQuery.data
  const providers = (providersQuery.data || []).filter(
    (provider) => provider.enabled && provider.type !== 'password' && typeof provider.id === 'string' && provider.id,
  )
  const passwordEnabled = options?.localPasswordLoginEnabled !== false
  const sliderEnabled = options?.verification.sliderEnabled === true

  useEffect(() => {
    if (options?.branding) applyBranding(options.branding)
  }, [options?.branding])

  useEffect(() => () => providerController.current?.abort(), [])

  const resetSliderVerification = () => {
    setSliderValue(0)
    setSliderVerified(false)
  }

  const login = async (values: { login: string; password: string }) => {
    if (sliderEnabled && !sliderVerified) {
      authAttemptPending.current = false
      setPending(false)
      message.warning(text.sliderVerificationRequired)
      return
    }
    try {
      const session = await loginWithPassword(values.login, values.password)
      const bootstrap = await getBootstrap()
      commitSession(session, bootstrap)
      applyBranding(bootstrap.branding)
      navigate('/home', { replace: true })
    } catch (error) {
      if (sliderEnabled) resetSliderVerification()
      const isCredentialError = error instanceof ApiError && (error.status === 401 || error.status === 403)
      message.error(isCredentialError ? text.loginFailed : readableError(error, text))
    } finally {
      authAttemptPending.current = false
      setPending(false)
    }
  }

  const loginProvider = async (provider: AuthProvider) => {
    if (!provider.id || authAttemptPending.current) return
    authAttemptPending.current = true
    const controller = new AbortController()
    providerController.current = controller
    setProviderPending(provider)
    try {
      const session = await loginWithProvider(provider.id, controller.signal)
      const bootstrap = await getBootstrap()
      commitSession(session, bootstrap)
      applyBranding(bootstrap.branding)
      navigate('/home', { replace: true })
    } catch (error) {
      if (!controller.signal.aborted) message.error(readableError(error, text))
    } finally {
      if (providerController.current === controller) {
        providerController.current = null
        setProviderPending(null)
      }
      authAttemptPending.current = false
    }
  }

  const cancelProviderLogin = () => {
    providerController.current?.abort()
    providerController.current = null
    setProviderPending(null)
  }

  if (optionsQuery.isLoading || providersQuery.isLoading) {
    return <div className="startup-state"><Skeleton active paragraph={{ rows: 5 }} /></div>
  }
  if (optionsQuery.isError || providersQuery.isError) {
    return (
      <Result
        extra={<Button icon={<ReloadOutlined />} onClick={() => void Promise.all([optionsQuery.refetch(), providersQuery.refetch()])}>{text.retry}</Button>}
        status="error"
        subTitle={text.offlineHelp}
        title={text.offlineTitle}
      />
    )
  }

  const logo = options?.branding?.loginLogoUrl
  return (
    <div className="login-screen">
      <header className="login-titlebar">
        <div className="login-brand">
          <img alt="" aria-hidden="true" className="brand-mark" src="/logo.svg" />
          <strong>{options?.branding?.appTitle || text.appName}</strong>
        </div>
      </header>
      <main className="login-main">
        <section className="login-panel">
          {logo ? <img alt="" className="login-logo" src={logo} /> : null}
          <h1>{providerPending ? text.organizationLoginWaiting : text.loginTitle}</h1>
          <p>{providerPending ? providerPending.name : text.loginDescription}</p>
          <div className="login-server"><i /> {host?.serverUrl}</div>
          {providerPending ? (
            <div aria-live="polite" className="provider-waiting" role="status">
              <Spin size="large" />
              <span>{text.organizationLoginHelp}</span>
              <Button onClick={cancelProviderLogin}>{text.cancel}</Button>
            </div>
          ) : (
            <>
              {!passwordEnabled ? <Alert showIcon title={text.passwordDisabled} type="info" /> : null}
              {passwordEnabled ? (
                <Form
                  layout="vertical"
                  onFinish={login}
                  onFinishFailed={() => {
                    authAttemptPending.current = false
                    setPending(false)
                  }}
                  onSubmitCapture={(event) => {
                    if (authAttemptPending.current) {
                      event.preventDefault()
                      return
                    }
                    authAttemptPending.current = true
                    setPending(true)
                  }}
                  requiredMark={false}
                >
                  <Form.Item label={text.username} name="login" rules={[{ required: true, message: text.username }]}>
                    <Input autoComplete="username" prefix={<UserOutlined />} />
                  </Form.Item>
                  <Form.Item label={text.password} name="password" rules={[{ required: true, message: text.password }]}>
                    <Input.Password autoComplete="current-password" prefix={<LockOutlined />} />
                  </Form.Item>
                  {sliderEnabled ? (
                    <Form.Item
                      extra={<span aria-live="polite">{sliderVerified ? text.sliderVerificationComplete : text.sliderVerificationHelp}</span>}
                      label={text.sliderVerification}
                    >
                      <Slider
                        ariaLabelForHandle={text.sliderVerification}
                        ariaValueTextFormatterForHandle={(value) => `${value}%`}
                        disabled={pending || sliderVerified}
                        max={100}
                        min={0}
                        onChange={setSliderValue}
                        onChangeComplete={(value) => {
                          if (value >= 98) {
                            setSliderValue(100)
                            setSliderVerified(true)
                            return
                          }
                          resetSliderVerification()
                        }}
                        step={1}
                        tooltip={{ formatter: null }}
                        value={sliderValue}
                      />
                    </Form.Item>
                  ) : null}
                  <Button block disabled={sliderEnabled && !sliderVerified} htmlType="submit" loading={pending} type="primary">
                    {text.signIn}
                  </Button>
                </Form>
              ) : null}
              {providers.length ? (
                <div aria-label={text.organizationLogin} className="provider-list">
                  <span>{text.organizationLogin}</span>
                  {providers.map((provider) => (
                    <Button
                      block
                      disabled={pending}
                      icon={<SafetyCertificateOutlined />}
                      key={provider.id}
                      onClick={() => void loginProvider(provider)}
                    >
                      {provider.name}
                    </Button>
                  ))}
                </div>
              ) : null}
              <Button block disabled={pending} onClick={() => navigate('/connect')} type="link">{text.backToConnection}</Button>
            </>
          )}
        </section>
      </main>
    </div>
  )
}

export function HomePage() {
  const text = useText()
  const queryClient = useQueryClient()
  const host = useAppStore((state) => state.host)
  const connection = useAppStore((state) => state.connection)
  const session = useAppStore((state) => state.session)
  const bootstrap = useAppStore((state) => state.bootstrap)
  const user = bootstrap?.currentUser || session?.user
  const permissions = bootstrap?.permissionSnapshot.permissionKeys || []
  const canReadAnnouncements = permissions.includes('system.announcements.view') ||
    permissions.includes('identity.portal.view')
  const inboxQuery = useQuery({
    queryKey: ['announcements', 'inbox'],
    queryFn: () => getAnnouncementInbox(5),
    enabled: canReadAnnouncements && connection?.status === 'online',
  })
  const readMutation = useMutation({
    mutationFn: markAnnouncementRead,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['announcements', 'inbox'] }),
  })

  return (
    <Page title={`${text.greeting}, ${displayName(user)}`} description={text.homeDescription}>
      <section className="status-band" aria-label={text.sessionStatus}>
        <div><CloudServerOutlined /><span><small>{text.currentServer}</small><strong title={host?.serverUrl}>{host?.serverUrl || '-'}</strong></span></div>
        <div><SafetyCertificateOutlined /><span><small>{text.sessionStatus}</small><strong>{connection ? connectionMessage(connection, text).title : text.checking}</strong></span></div>
        <div><UserOutlined /><span><small>{text.signedInAs}</small><strong>{user?.email || '-'}</strong></span></div>
      </section>
      <section className="page-section">
        <header className="section-heading">
          <h2>{text.announcements}</h2>
          {inboxQuery.data?.unreadCount ? <Tag color="blue">{inboxQuery.data.unreadCount} {text.unread}</Tag> : null}
        </header>
        {!canReadAnnouncements ? <Empty description={text.announcementNoAccess} image={Empty.PRESENTED_IMAGE_SIMPLE} /> : null}
        {inboxQuery.isLoading ? <Skeleton active paragraph={{ rows: 3 }} /> : null}
        {inboxQuery.isError ? (
          <Alert
            action={<Button onClick={() => void inboxQuery.refetch()} size="small">{text.retry}</Button>}
            description={readableError(inboxQuery.error, text)}
            showIcon
            title={text.announcementServiceUnavailable}
            type="warning"
          />
        ) : null}
        {inboxQuery.data && !inboxQuery.data.items.length ? <Empty description={text.noAnnouncements} image={Empty.PRESENTED_IMAGE_SIMPLE} /> : null}
        {inboxQuery.data?.items.length ? (
          <div className="announcement-list">
            {inboxQuery.data.items.map((announcement) => (
              <article className={announcement.isRead ? '' : 'unread'} key={announcement.id}>
                <div>
                  <h3>{announcement.title}</h3>
                  <p>{announcement.summary}</p>
                </div>
                {!announcement.isRead ? (
                  <Button
                    aria-label={`${text.markRead}: ${announcement.title}`}
                    icon={<CheckOutlined />}
                    loading={readMutation.isPending && readMutation.variables === announcement.id}
                    onClick={() => readMutation.mutate(announcement.id)}
                    title={text.markRead}
                    type="text"
                  />
                ) : null}
              </article>
            ))}
          </div>
        ) : null}
      </section>
    </Page>
  )
}

export function ProfilePage() {
  const { message } = App.useApp()
  const text = useText()
  const [profileForm] = Form.useForm<ProfileUpdate>()
  const [passwordForm] = Form.useForm<{ currentPassword: string; newPassword: string; confirmPassword: string }>()
  const session = useAppStore((state) => state.session)
  const updateSummary = useAppStore((state) => state.updateProfileSummary)
  const profileQuery = useQuery({ queryKey: ['auth', 'profile'], queryFn: getProfile })
  const profile = profileQuery.data
  const updateMutation = useMutation({
    mutationFn: updateProfile,
    onSuccess: (updated) => {
      updateSummary(updated)
      profileQuery.refetch()
      message.success(text.profileSaved)
    },
    onError: (error) => message.error(readableError(error, text)),
  })
  const passwordMutation = useMutation({
    mutationFn: (input: { currentPassword: string; newPassword: string }) =>
      changePassword(input.currentPassword, input.newPassword),
    onSuccess: () => {
      passwordForm.resetFields()
      message.success(text.passwordChanged)
    },
    onError: (error) => message.error(readableError(error, text)),
  })

  useEffect(() => {
    if (!profile) return
    profileForm.setFieldsValue({
      displayName: profile.displayName,
      email: profile.email,
      phone: profile.phone,
      avatarUrl: profile.avatarUrl,
      avatarFit: profile.avatarFit || 'cover',
    })
  }, [profile, profileForm])

  if (profileQuery.isLoading) return <Page title={text.profile} description={text.profileDescription}><Skeleton active paragraph={{ rows: 8 }} /></Page>
  if (profileQuery.isError || !profile) {
    return <Page title={text.profile} description={text.profileDescription}><Result extra={<Button onClick={() => void profileQuery.refetch()}>{text.retry}</Button>} status="error" title={text.offlineTitle} /></Page>
  }
  const hasPasswordIdentity = profile.identities.some((identity) => identity.providerType === 'password')

  return (
    <Page title={text.profile} description={text.profileDescription}>
      <section className="profile-summary">
        <Avatar icon={<UserOutlined />} size={72} src={profile.avatarUrl || avatarURL(session?.user)} />
        <div><h2>{profile.displayName || profile.username}</h2><p>{profile.email}</p><Tag color="success">{profile.status}</Tag></div>
      </section>
      <section className="page-section">
        <h2>{text.account}</h2>
        <Descriptions
          column={2}
          items={[
            { key: 'username', label: text.username, children: profile.username },
            { key: 'roles', label: text.roles, children: profile.roles.join(', ') || text.noValue },
            { key: 'teams', label: text.teams, children: profile.teams.join(', ') || text.noValue },
            { key: 'projects', label: text.projects, children: profile.projects.join(', ') || text.noValue },
            { key: 'identities', label: text.identities, span: 2, children: profile.identities.map((identity) => identity.displayName || identity.providerId || identity.providerType).join(', ') || text.noValue },
          ]}
        />
      </section>
      <section className="page-section form-section">
        <h2>{text.edit}</h2>
        <Form form={profileForm} layout="vertical" onFinish={(values) => updateMutation.mutate(values)} requiredMark={false}>
          <div className="form-grid">
            <Form.Item label={text.displayName} name="displayName" rules={[{ required: true, message: text.displayName }]}><Input autoComplete="name" /></Form.Item>
            <Form.Item label={text.email} name="email" rules={[{ required: true, type: 'email', message: text.email }]}><Input autoComplete="email" type="email" /></Form.Item>
            <Form.Item label={text.phone} name="phone"><Input autoComplete="tel" /></Form.Item>
            <Form.Item label={text.avatarFit} name="avatarFit"><Select options={[{ label: text.avatarCover, value: 'cover' }, { label: text.avatarContain, value: 'contain' }]} /></Form.Item>
            <Form.Item className="span-two" label={text.avatarUrl} name="avatarUrl"><Input autoComplete="photo" type="url" /></Form.Item>
          </div>
          <Button htmlType="submit" loading={updateMutation.isPending} type="primary">{text.save}</Button>
        </Form>
      </section>
      <section className="page-section form-section">
        <h2>{text.changePassword}</h2>
        {!hasPasswordIdentity ? <Alert showIcon title={text.externalPassword} type="info" /> : (
          <Form
            form={passwordForm}
            layout="vertical"
            onFinish={(values) => passwordMutation.mutate({ currentPassword: values.currentPassword, newPassword: values.newPassword })}
            requiredMark={false}
          >
            <input autoComplete="username" hidden name="username" readOnly type="text" value={profile.username} />
            <div className="form-grid">
              <Form.Item label={text.currentPassword} name="currentPassword" rules={[{ required: true, message: text.currentPassword }]}><Input.Password autoComplete="current-password" /></Form.Item>
              <span />
              <Form.Item label={text.newPassword} name="newPassword" rules={[{ required: true, min: 8, message: text.newPassword }]}><Input.Password autoComplete="new-password" /></Form.Item>
              <Form.Item
                dependencies={['newPassword']}
                label={text.confirmPassword}
                name="confirmPassword"
                rules={[
                  { required: true, message: text.confirmPassword },
                  ({ getFieldValue }) => ({ validator: (_, value) => !value || getFieldValue('newPassword') === value ? Promise.resolve() : Promise.reject(new Error(text.passwordMismatch)) }),
                ]}
              ><Input.Password autoComplete="new-password" /></Form.Item>
            </div>
            <Button htmlType="submit" loading={passwordMutation.isPending} type="primary">{text.changePassword}</Button>
          </Form>
        )}
      </section>
    </Page>
  )
}

export function SettingsPage() {
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const { message } = App.useApp()
  const text = useText()
  const [serverForm] = Form.useForm<{ serverUrl: string }>()
  const pendingServerURL = Form.useWatch('serverUrl', serverForm)
  const [serverModalOpen, setServerModalOpen] = useState(false)
  const [switching, setSwitching] = useState(false)
  const [switchError, setSwitchError] = useState<string | null>(null)
  const host = useAppStore((state) => state.host)
  const session = useAppStore((state) => state.session)
  const themeMode = useAppStore((state) => state.themeMode)
  const locale = useAppStore((state) => state.locale)
  const setThemeMode = useAppStore((state) => state.setThemeMode)
  const setLocale = useAppStore((state) => state.setLocale)
  const setHost = useAppStore((state) => state.setHost)
  const setConnection = useAppStore((state) => state.setConnection)
  const clearSession = useAppStore((state) => state.clearSession)

  const openServerModal = () => {
    serverForm.setFieldValue('serverUrl', host?.serverUrl || '')
    setSwitchError(null)
    setServerModalOpen(true)
  }
  const switchServer = async () => {
    const { serverUrl } = await serverForm.validateFields()
    let preparedConnection: ConnectionCheck | null = null
    let sessionCleared = false
    setSwitching(true)
    setSwitchError(null)
    try {
      const checked = await checkServer(serverUrl)
      if (checked.status !== 'online') {
        const copy = connectionMessage(checked, text)
        setSwitchError(`${copy.title}: ${copy.description}`)
        return
      }
      if (checked.serverUrl === host?.serverUrl) {
        setServerModalOpen(false)
        return
      }
      await queryClient.cancelQueries()
      const prepared = await prepareServerSwitch(checked.serverUrl, session?.accessToken)
      preparedConnection = prepared.connection
      clearSession()
      sessionCleared = true
      queryClient.clear()
      const nextHost = await activateServerSwitch(prepared.activationToken)
      setHost(nextHost)
      setConnection(prepared.connection)
      setServerModalOpen(false)
      navigate('/login', { replace: true })
    } catch (error) {
      const activated = preparedConnection
        ? await recoverHostAfterSwitch(preparedConnection, setHost, setConnection).catch(() => false)
        : false
      const errorMessage = readableError(error, text)
      if (sessionCleared) {
        if (!activated) message.error(errorMessage)
        navigate('/login', { replace: true })
      } else {
        setSwitchError(errorMessage)
      }
    } finally {
      setSwitching(false)
    }
  }

  const app = host?.app
  return (
    <Page title={text.settings} description={text.settingsDescription}>
      <section className="settings-section">
        <h2>{text.appearance}</h2>
        <SettingRow label={text.theme}>
          <Segmented
            onChange={(value) => setThemeMode(value as ThemeMode)}
            options={[
              { label: text.themeSystem, value: 'system' },
              { label: text.themeLight, value: 'light' },
              { label: text.themeDark, value: 'dark' },
            ]}
            value={themeMode}
          />
        </SettingRow>
        <SettingRow label={text.language}>
          <Segmented
            onChange={(value) => setLocale(value as LocaleCode)}
            options={[{ label: '简体中文', value: 'zh_CN' }, { label: 'English', value: 'en_US' }]}
            value={locale}
          />
        </SettingRow>
      </section>
      <section className="settings-section">
        <h2>{text.connection}</h2>
        <SettingRow description={host?.serverUrl} label={text.currentServer}>
          {host?.managedByEnvironment ? <Tag>{text.environmentManaged}</Tag> : (
            <Button onClick={openServerModal}>{text.changeServer}</Button>
          )}
        </SettingRow>
      </section>
      <section className="settings-section">
        <h2>{text.about}</h2>
        <Descriptions
          column={1}
          items={[
            { key: 'version', label: text.version, children: app?.version || '-' },
            { key: 'platform', label: text.platform, children: app ? `${app.platform} / ${app.arch}` : '-' },
            { key: 'logs', label: text.logDirectory, children: app?.logDirectory || '-' },
            { key: 'updates', label: text.updateStatus, children: text.updateUnavailable },
          ]}
        />
        <Button
          icon={<FolderOpenOutlined />}
          onClick={() => void openLogDirectory().catch((error) => message.error(readableError(error, text)))}
        >
          {text.openLogs}
        </Button>
      </section>
      <Modal
        cancelText={text.cancel}
        confirmLoading={switching}
        destroyOnHidden
        mask={{ closable: false }}
        okText={text.changeServer}
        onCancel={() => setServerModalOpen(false)}
        onOk={() => void switchServer()}
        open={serverModalOpen}
        title={text.changeServer}
      >
        <Descriptions
          className="server-switch-addresses"
          column={1}
          items={[
            { key: 'current', label: text.currentServer, children: host?.serverUrl || '-' },
            { key: 'next', label: text.newServer, children: pendingServerURL || '-' },
          ]}
          size="small"
        />
        <Alert description={text.changeServerWarning} showIcon type="warning" />
        <Form form={serverForm} layout="vertical" requiredMark={false}>
          <Form.Item label={text.serverAddress} name="serverUrl" rules={[{ required: true, message: text.invalidAddress }]}>
            <Input autoCapitalize="none" autoComplete="url" autoCorrect="off" spellCheck={false} />
          </Form.Item>
        </Form>
        {switchError ? <Alert showIcon title={switchError} type="error" /> : null}
      </Modal>
    </Page>
  )
}

export function Page({ title, description, children }: { title: string; description: string; children: ReactNode }) {
  return <div className="page"><header className="page-heading"><h1>{title}</h1><p>{description}</p></header>{children}</div>
}

function SettingRow({ label, description, children }: { label: string; description?: string; children: ReactNode }) {
  return <div className="setting-row"><span><strong>{label}</strong>{description ? <small title={description}>{description}</small> : null}</span><div>{children}</div></div>
}

async function recoverHostAfterSwitch(
  attemptedConnection: ConnectionCheck,
  setHost: (host: HostState) => void,
  setConnection: (connection: ConnectionCheck) => void,
) {
  const currentHost = await getHostState()
  setHost(currentHost)
  const activated = currentHost.serverUrl === attemptedConnection.serverUrl
  setConnection(activated ? attemptedConnection : await checkServer(currentHost.serverUrl))
  return activated
}

export function connectionMessage(connection: ConnectionCheck, text: Text) {
  switch (connection.status) {
    case 'unconfigured': return { title: text.unconfiguredTitle, description: text.unconfiguredHelp }
    case 'checking': return { title: text.checking, description: connection.serverUrl }
    case 'not_ready': return { title: text.notReadyTitle, description: text.notReadyHelp }
    case 'tls_error': return { title: text.tlsTitle, description: text.tlsHelp }
    case 'incompatible': return { title: text.incompatibleTitle, description: text.incompatibleHelp }
    case 'offline': return { title: text.offlineTitle, description: text.offlineHelp }
    case 'online': return { title: text.connected, description: connection.serverUrl }
  }
}

function readableError(error: unknown, text: Text): string {
  if (error instanceof HostError || error instanceof ApiError) {
    let message = error.message
    if (error.code === 'network_error' || error.code === 'host_unavailable') message = text.offlineHelp
    if (error.code === 'configuration_managed') message = text.managedAddress
    return error.requestId ? `${message} (${text.requestId}: ${error.requestId})` : message
  }
  return text.offlineHelp
}
