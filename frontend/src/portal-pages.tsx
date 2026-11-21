import { useEffect, useMemo, useState } from 'react'
import {
  AppstoreOutlined,
  ArrowLeftOutlined,
  LinkOutlined,
  LoadingOutlined,
  SearchOutlined,
  StarFilled,
  StarOutlined,
  TeamOutlined,
  UserOutlined,
} from '@ant-design/icons'
import { Alert, App, Avatar, Button, Descriptions, Empty, Input, Segmented, Skeleton, Tag, Typography } from 'antd'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useNavigate, useParams } from 'react-router-dom'
import {
  ApiError,
  buildWebMyAppsURL,
  getPortalApplication,
  getPortalBootstrap,
  getPortalColleagueApps,
  launchPortalApplication,
  setPortalFavorite,
  validateExternalHostedAppURL,
} from '@/api'
import { type Text, useText } from '@/i18n'
import { openBrowserURL } from '@/native/host'
import { Page } from '@/pages'
import { useAppStore } from '@/store'
import type {
  HostedAppKind,
  IdentityApplication,
  PortalHostedAppAuthorSummary,
  PortalHostedAppCatalog,
  PortalHostedAppItem,
  PortalLaunchDecision,
} from '@/types'
import './portal-network.css'

type PortalView = 'all' | 'favorites' | 'colleague_works'

export function PortalPage() {
  const { message } = App.useApp()
  const text = useText()
  const [search, setSearch] = useState('')
  const [category, setCategory] = useState('')
  const [view, setView] = useState<PortalView>('all')
  const [colleagueKind, setColleagueKind] = useState<'' | HostedAppKind>('')
  const [selectedAuthor, setSelectedAuthor] = useState<PortalHostedAppAuthorSummary | null>(null)
  const debouncedColleagueQuery = useDebouncedSearch(view === 'colleague_works' ? search : '')
  const compactCards = useAppStore((state) => state.portalCardSize === 'compact')
  const serverURL = useAppStore((state) => state.host?.serverUrl)
  const bootstrapPermissions = useAppStore((state) => state.bootstrap?.permissionSnapshot.permissionKeys)
  const portal = useQuery({ queryKey: ['portal', 'bootstrap'], queryFn: getPortalBootstrap })
  const colleagueSummary = useQuery({
    queryKey: ['portal', 'colleague-apps', { query: '', kind: undefined, authorUserId: undefined }],
    queryFn: () => getPortalColleagueApps({ limit: 24 }),
    staleTime: 30_000,
    retry: false,
  })
  const colleagueParams = useMemo(() => ({
    query: debouncedColleagueQuery || undefined,
    kind: colleagueKind || undefined,
    authorUserId: selectedAuthor?.userId || undefined,
    limit: 24,
  }), [colleagueKind, debouncedColleagueQuery, selectedAuthor?.userId])
  const colleagueCatalog = useQuery({
    queryKey: ['portal', 'colleague-apps', {
      query: colleagueParams.query || '',
      kind: colleagueParams.kind,
      authorUserId: colleagueParams.authorUserId,
    }],
    queryFn: () => getPortalColleagueApps(colleagueParams),
    enabled: view === 'colleague_works',
    retry: false,
  })
  const actions = usePortalActions()
  const categories = useMemo(() => Array.from(new Set([
    ...(portal.data?.categories || []),
    ...(portal.data?.applications || []).map(applicationGroup),
  ].filter(Boolean))), [portal.data?.applications, portal.data?.categories])
  const applications = useMemo(() => {
    const needle = search.trim().toLocaleLowerCase()
    const source = view === 'favorites' ? portal.data?.favorites : portal.data?.applications
    return (source || []).filter((application) => {
      if (category && applicationGroup(application) !== category) return false
      if (!needle) return true
      return [application.name, application.slug, application.description, application.category, application.providerType, ...(application.tags || [])]
        .some((value) => value?.toLocaleLowerCase().includes(needle))
    })
  }, [category, portal.data?.applications, portal.data?.favorites, search, view])
  const myAppsCount = colleagueCatalog.data?.myAppsCount ?? colleagueSummary.data?.myAppsCount ?? 0
  const hasAppHostingPermission = useMemo(() => {
    const keys = new Set([
      ...(bootstrapPermissions || []),
      ...(portal.data?.principal.permissionKeys || []),
    ])
    return keys.has('apphosting.apps.view') || keys.has('apphosting.apps.publish')
  }, [bootstrapPermissions, portal.data?.principal.permissionKeys])
  const showMyAppsButton = hasAppHostingPermission || myAppsCount > 0

  const openMyAppsInBrowser = () => {
    if (!serverURL) {
      message.error(text.portalLaunchFailed)
      return
    }
    try {
      const myAppsURL = buildWebMyAppsURL(serverURL)
      void openBrowserURL(myAppsURL).catch(() => message.error(text.portalLaunchFailed))
    } catch {
      message.error(text.portalLaunchFailed)
    }
  }

  if (portal.isLoading) {
    return <Page title={text.portal}><Skeleton active paragraph={{ rows: 8 }} /></Page>
  }
  if (portal.isError || !portal.data) {
    const failure = portalFailure(portal.error, text)
    return (
      <Page title={text.portal}>
        <Alert
          action={<Button onClick={() => void portal.refetch()} size="small">{text.retry}</Button>}
          description={failure.description}
          showIcon
          title={failure.title}
          type="error"
        />
      </Page>
    )
  }

  const searchLabel = view === 'colleague_works' ? text.portalColleagueSearch : text.portalSearch

  return (
    <Page title={text.portal}>
      <div className="portal-toolbar portal-catalog-toolbar">
        <div className="portal-toolbar-main">
          <Input
            allowClear
            aria-label={searchLabel}
            onChange={(event) => setSearch(event.target.value)}
            placeholder={searchLabel}
            prefix={<SearchOutlined />}
            value={search}
          />
          <div className="portal-toolbar-controls">
            <Segmented
              aria-label={text.portal}
              onChange={(value) => {
                const nextView: PortalView =
                  value === 'favorites'
                    ? 'favorites'
                    : value === 'colleague_works'
                      ? 'colleague_works'
                      : 'all'
                setView(nextView)
              }}
              options={[
                { label: text.portalApplications, value: 'all' },
                { icon: <StarOutlined />, label: text.portalFavorites, value: 'favorites' },
                { icon: <TeamOutlined />, label: text.portalColleagueWorks, value: 'colleague_works' },
              ]}
              value={view}
            />
            {showMyAppsButton ? (
              <Button
                aria-label={text.portalMyApps}
                className="portal-my-apps-btn"
                icon={<LinkOutlined />}
                onClick={openMyAppsInBrowser}
              >
                {myAppsCount > 0 ? `${text.portalMyApps} (${myAppsCount})` : text.portalMyApps}
              </Button>
            ) : null}
          </div>
        </div>
        {view === 'colleague_works' ? (
          <div className="portal-categories" role="group" aria-label={text.portalColleagueType}>
            <Button aria-pressed={!colleagueKind} onClick={() => setColleagueKind('')} size="small" type="default">{text.portalAll}</Button>
            <Button aria-pressed={colleagueKind === 'static'} onClick={() => setColleagueKind('static')} size="small" type="default">{text.portalHostedKindStatic}</Button>
            <Button aria-pressed={colleagueKind === 'dynamic'} onClick={() => setColleagueKind('dynamic')} size="small" type="default">{text.portalHostedKindDynamic}</Button>
          </div>
        ) : (
          <div className="portal-categories" role="group" aria-label={text.portalCategory}>
            <Button aria-pressed={!category} onClick={() => setCategory('')} size="small" type="default">{text.portalAll}</Button>
            {categories.map((item) => (
              <Button aria-pressed={category === item} key={item} onClick={() => setCategory(item)} size="small" type="default">{item}</Button>
            ))}
          </div>
        )}
      </div>

      <section aria-live="polite" className="portal-section">
        {view === 'colleague_works' ? (
          <ColleagueWorksSection
            catalog={colleagueCatalog.data}
            compact={compactCards}
            error={colleagueCatalog.error}
            hasFilter={Boolean(debouncedColleagueQuery || colleagueKind)}
            isError={colleagueCatalog.isError}
            isLoading={colleagueCatalog.isLoading}
            onClearAuthor={() => setSelectedAuthor(null)}
            onRetry={() => void colleagueCatalog.refetch()}
            onSelectAuthor={(author) => {
              setSelectedAuthor(author)
              setSearch('')
            }}
            selectedAuthor={selectedAuthor}
            serverURL={serverURL}
          />
        ) : applications.length ? (
          <PortalGrid
            applications={applications}
            actions={actions}
            compact={compactCards}
          />
        ) : <Empty description={search || category ? text.portalNoMatches : view === 'favorites' ? text.portalNoFavorites : text.portalEmpty} image={Empty.PRESENTED_IMAGE_SIMPLE} />}
      </section>
    </Page>
  )
}

export function PortalApplicationPage() {
  const text = useText()
  const navigate = useNavigate()
  const { applicationId = '' } = useParams()
  const application = useQuery({
    queryKey: ['portal', 'applications', applicationId],
    queryFn: () => getPortalApplication(applicationId),
    enabled: Boolean(applicationId),
  })
  const actions = usePortalActions()
  const serverURL = useAppStore((state) => state.host?.serverUrl)

  if (application.isLoading) {
    return <Page description={text.portalDescription} title={text.portal}><Skeleton active paragraph={{ rows: 6 }} /></Page>
  }
  if (application.isError || !application.data) {
    const failure = portalFailure(application.error, text)
    return (
      <Page description={text.portalDescription} title={text.portal}>
        <Alert
          action={<Button onClick={() => void application.refetch()} size="small">{text.retry}</Button>}
          description={failure.description}
          showIcon
          title={failure.title}
          type="error"
        />
      </Page>
    )
  }

  const item = application.data
  return (
    <Page description={item.description || text.portalDescription} title={item.name}>
      <Button icon={<ArrowLeftOutlined />} onClick={() => navigate('/portal')} type="link">{text.portalBack}</Button>
      <div className="portal-detail">
        <Avatar
          alt={item.name}
          icon={<AppstoreOutlined />}
          shape="square"
          size={64}
          src={applicationImageURL(item.iconUrl, serverURL)}
        />
        <div>
          <div className="portal-detail-actions">
            <Button
              icon={item.favorite ? <StarFilled /> : <StarOutlined />}
              loading={actions.favorite.isPending}
              onClick={() => actions.favorite.mutate({ application: item, favorite: !item.favorite })}
            >
              {item.favorite ? text.portalUnfavorite : text.portalFavorite}
            </Button>
            <Button
              icon={<LinkOutlined />}
              loading={actions.launch.isPending}
              onClick={() => actions.launch.mutate(item)}
              type="primary"
            >
              {text.portalOpen}
            </Button>
          </div>
          <Descriptions
            column={1}
            items={[
              { key: 'provider', label: text.portalProvider, children: item.providerType || '—' },
              { key: 'category', label: text.portalCategory, children: item.category || '—' },
              { key: 'status', label: text.portalStatus, children: item.status },
              { key: 'tags', label: 'Tags', children: item.tags?.map((tag) => <Tag key={tag}>{tag}</Tag>) || '—' },
              { key: 'lastLaunch', label: text.portalLastLaunched, children: item.lastLaunchedAt || '—' },
              { key: 'metadata', label: text.portalMetadata, children: item.metadata && Object.keys(item.metadata).length ? JSON.stringify(item.metadata) : '—' },
            ]}
          />
        </div>
      </div>
    </Page>
  )
}

function PortalGrid({ applications, actions, compact }: {
  applications: IdentityApplication[]
  actions: ReturnType<typeof usePortalActions>
  compact: boolean
}) {
  const text = useText()
  const serverURL = useAppStore((state) => state.host?.serverUrl)
  return (
    <div className={`portal-grid portal-tile-grid${compact ? ' compact' : ''}`}>
      {applications.map((application) => {
        const launching = actions.launch.isPending && actions.launch.variables?.id === application.id
        const category = application.category?.trim()
        return (
          <article className="portal-card" key={application.id}>
            <button
              aria-busy={launching}
              aria-label={`${text.portalOpen} ${application.name}`}
              className="portal-card-launch"
              disabled={launching}
              onClick={() => actions.launch.mutate(application)}
              type="button"
            >
              <Avatar
                alt={application.name}
                className="portal-card-icon"
                icon={launching ? <LoadingOutlined spin /> : <AppstoreOutlined />}
                shape="square"
                size={compact ? 30 : 38}
                src={launching ? undefined : applicationImageURL(application.iconUrl, serverURL)}
              />
              <span className="portal-card-identity">
                <strong>{application.name}</strong>
                {category ? <span className="portal-card-category">{category}</span> : null}
              </span>
              {compact ? null : <span className="portal-card-description">{application.description || application.slug}</span>}
            </button>
            <Button
              aria-label={`${application.favorite ? text.portalUnfavorite : text.portalFavorite} ${application.name}`}
              aria-pressed={Boolean(application.favorite)}
              className="portal-card-favorite"
              icon={application.favorite ? <StarFilled /> : <StarOutlined />}
              loading={actions.favorite.isPending && actions.favorite.variables?.application.id === application.id}
              onClick={() => actions.favorite.mutate({ application, favorite: !application.favorite })}
              title={application.favorite ? text.portalUnfavorite : text.portalFavorite}
              type="text"
            />
          </article>
        )
      })}
    </div>
  )
}

function applicationGroup(application: IdentityApplication): string {
  return application.category?.trim() || application.providerType?.trim() || ''
}

function applicationImageURL(raw: string | undefined, serverURL: string | undefined): string | undefined {
  const value = raw?.trim()
  if (!value) return undefined
  if (value.length <= 700_000 && /^data:image\/(?:png|jpeg|webp|ico|x-icon|vnd\.microsoft\.icon);base64,[a-z\d+/]+={0,2}$/i.test(value)) {
    return value
  }
  if (!serverURL) return undefined
  try {
    const server = new URL(serverURL)
    const image = new URL(value, server)
    if (image.protocol === 'https:' || (image.protocol === 'http:' && image.origin === server.origin)) {
      return image.toString()
    }
  } catch {
    // Invalid and unsafe image links fall back to the application icon.
  }
  return undefined
}

function usePortalActions() {
  const { message } = App.useApp()
  const text = useText()
  const queryClient = useQueryClient()
  const serverURL = useAppStore((state) => state.host?.serverUrl)
  const favorite = useMutation({
    mutationFn: ({ application, favorite }: { application: IdentityApplication; favorite: boolean }) =>
      setPortalFavorite(application.id, favorite),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['portal'] }),
    onError: (error) => message.error(errorMessage(error)),
  })
  const launch = useMutation({
    mutationFn: async (application: IdentityApplication) => {
      if (!serverURL) throw new Error(text.portalLaunchFailed)
      const decision = await launchPortalApplication(application.id)
      await openBrowserURL(browserHandoffURL(serverURL, decision))
    },
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['portal'] }),
    onError: () => message.error(text.portalLaunchFailed),
  })
  return { favorite, launch }
}

function browserHandoffURL(serverURL: string, decision: PortalLaunchDecision): string {
  if (!decision.handoffExpiresAt) throw new Error('Missing browser handoff')
  const server = new URL(serverURL)
  const handoff = new URL(decision.launchUrl, server)
  const prefix = '/auth/browser-handoff/'
  if ((server.protocol !== 'http:' && server.protocol !== 'https:') || handoff.origin !== server.origin ||
    handoff.username || handoff.password || handoff.search || handoff.hash ||
    !handoff.pathname.startsWith(prefix) || handoff.pathname.length === prefix.length) {
    throw new Error('Invalid browser handoff')
  }
  return handoff.toString()
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : 'Request failed'
}

function portalFailure(error: unknown, text: Text) {
  if (error instanceof ApiError && error.code === 'network_error') {
    return { title: text.offlineTitle, description: text.offlineHelp }
  }
  return { title: text.portalLoadFailed, description: errorMessage(error) }
}

function colleagueFailure(error: unknown, text: Text) {
  if (error instanceof ApiError && error.code === 'network_error') {
    return { title: text.offlineTitle, description: text.offlineHelp }
  }
  return { title: text.portalColleagueLoadFailed, description: errorMessage(error) }
}

function useDebouncedSearch(raw: string): string {
  const trimmed = raw.trim()
  const [debounced, setDebounced] = useState(trimmed)
  useEffect(() => {
    if (!trimmed) {
      setDebounced('')
      return
    }
    const timer = window.setTimeout(() => setDebounced(trimmed), 120)
    return () => window.clearTimeout(timer)
  }, [trimmed])
  return debounced
}

function formatPortalTimestamp(value: string): string {
  const parsed = Date.parse(value)
  if (Number.isNaN(parsed)) return value
  return new Date(parsed).toLocaleString()
}

function ColleagueWorksSection({
  catalog,
  compact,
  error,
  hasFilter,
  isError,
  isLoading,
  onClearAuthor,
  onRetry,
  onSelectAuthor,
  selectedAuthor,
  serverURL,
}: {
  catalog: PortalHostedAppCatalog | undefined
  compact: boolean
  error: unknown
  hasFilter: boolean
  isError: boolean
  isLoading: boolean
  onClearAuthor: () => void
  onRetry: () => void
  onSelectAuthor: (author: PortalHostedAppAuthorSummary) => void
  selectedAuthor: PortalHostedAppAuthorSummary | null
  serverURL: string | undefined
}) {
  const { message } = App.useApp()
  const text = useText()
  const openHosted = useMutation({
    mutationFn: async (item: PortalHostedAppItem) => {
      const safeURL = validateExternalHostedAppURL(item.url, serverURL)
      await openBrowserURL(safeURL)
    },
    onError: () => message.error(text.portalLaunchFailed),
  })

  if (isLoading) {
    return <Skeleton active paragraph={{ rows: 6 }} />
  }
  if (isError || !catalog) {
    const failure = colleagueFailure(error, text)
    return (
      <Alert
        action={<Button onClick={onRetry} size="small">{text.retry}</Button>}
        description={failure.description}
        showIcon
        title={failure.title}
        type="error"
      />
    )
  }

  const activeAuthor = selectedAuthor ? (catalog.selectedAuthor ?? selectedAuthor) : null
  const showAuthors = !activeAuthor && catalog.authors.length > 0

  return (
    <div className="portal-colleague-works">
      {activeAuthor ? (
        <div className="portal-author-banner">
          <Button
            icon={<ArrowLeftOutlined />}
            onClick={onClearAuthor}
            size="small"
            type="link"
          >
            {text.portalBackToColleagueWorks}
          </Button>
          <div className="portal-author-banner-profile">
            <Avatar
              alt={activeAuthor.displayName}
              className="portal-card-icon"
              icon={<UserOutlined />}
              size={40}
              src={applicationImageURL(activeAuthor.avatarUrl, serverURL)}
            />
            <div className="portal-author-banner-meta">
              <div className="portal-author-name-row">
                <strong>{activeAuthor.displayName}</strong>
                {activeAuthor.teamNames.map((team) => (
                  <Tag key={team}>{team}</Tag>
                ))}
              </div>
              <span className="portal-author-count">
                {activeAuthor.visibleAppCount} {text.portalVisibleWorksSuffix}
              </span>
            </div>
          </div>
        </div>
      ) : null}

      {showAuthors ? (
        <div aria-label={text.portalColleagueAuthors} className="portal-authors-section" role="region">
          <h2 className="portal-subsection-title">{text.portalColleagueAuthors}</h2>
          <div className="portal-author-grid">
            {catalog.authors.map((author) => (
              <button
                aria-label={`${author.displayName} ${author.teamNames.join(' ')}`.trim()}
                className="portal-card portal-author-card"
                key={author.userId}
                onClick={() => onSelectAuthor(author)}
                type="button"
              >
                <Avatar
                  alt={author.displayName}
                  className="portal-card-icon"
                  icon={<UserOutlined />}
                  size={38}
                  src={applicationImageURL(author.avatarUrl, serverURL)}
                />
                <span className="portal-author-card-body">
                  <span className="portal-author-name-row">
                    <strong>{author.displayName}</strong>
                    {author.teamNames.map((team) => (
                      <Tag key={team}>{team}</Tag>
                    ))}
                  </span>
                  <span className="portal-author-count">
                    {author.visibleAppCount} {text.portalVisibleWorksSuffix}
                  </span>
                </span>
              </button>
            ))}
          </div>
        </div>
      ) : null}

      {catalog.items.length ? (
        <div className={`portal-grid portal-hosted-grid${compact ? ' compact' : ''}`}>
          {catalog.items.map((item) => {
            const opening = openHosted.isPending && openHosted.variables?.id === item.id
            return (
              <article className="portal-card portal-hosted-card" key={item.id}>
                <div className="portal-hosted-header">
                  <strong>{item.name}</strong>
                  <Tag color={item.kind === 'dynamic' ? 'geekblue' : 'blue'}>
                    {item.kind === 'dynamic' ? text.portalHostedKindDynamic : text.portalHostedKindStatic}
                  </Tag>
                </div>
                <p className="portal-hosted-description">
                  {item.description || text.portalColleagueNoDescription}
                </p>
                <div className="portal-hosted-author">
                  <Avatar
                    alt={item.author.displayName}
                    icon={<UserOutlined />}
                    size={22}
                    src={applicationImageURL(item.author.avatarUrl, serverURL)}
                  />
                  <span>{item.author.displayName}</span>
                  {item.author.teamNames.map((team) => (
                    <Tag key={team}>{team}</Tag>
                  ))}
                </div>
                <div className="portal-hosted-footer">
                  <span className="portal-hosted-updated">
                    {text.portalColleagueUpdatedAt} {formatPortalTimestamp(item.updatedAt)}
                  </span>
                  <Button
                    aria-label={`${text.portalOpen} ${item.name}`}
                    icon={<LinkOutlined />}
                    loading={opening}
                    onClick={() => openHosted.mutate(item)}
                    size="small"
                    type="primary"
                  >
                    {text.portalOpen}
                  </Button>
                </div>
              </article>
            )
          })}
        </div>
      ) : !showAuthors ? (
        hasFilter || Boolean(activeAuthor) ? (
          <Empty description={text.portalColleagueNoMatches} image={Empty.PRESENTED_IMAGE_SIMPLE} />
        ) : (
          <Empty description={text.portalColleagueEmpty} image={Empty.PRESENTED_IMAGE_SIMPLE}>
            <Typography.Paragraph className="portal-colleague-empty-help" type="secondary">
              {text.portalColleagueEmptyHelp}
            </Typography.Paragraph>
          </Empty>
        )
      ) : null}
    </div>
  )
}
