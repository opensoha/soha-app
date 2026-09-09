import { useMemo, useState } from 'react'
import {
  AppstoreOutlined,
  ArrowLeftOutlined,
  InfoCircleOutlined,
  LinkOutlined,
  SearchOutlined,
  StarFilled,
  StarOutlined,
} from '@ant-design/icons'
import { Alert, App, Avatar, Button, Descriptions, Empty, Input, Segmented, Skeleton, Tag } from 'antd'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useNavigate, useParams } from 'react-router-dom'
import {
  ApiError,
  getPortalApplication,
  getPortalBootstrap,
  launchPortalApplication,
  setPortalFavorite,
} from '@/api'
import { type Text, useText } from '@/i18n'
import { openBrowserURL } from '@/native/host'
import { Page } from '@/pages'
import { useAppStore } from '@/store'
import type { IdentityApplication, PortalLaunchDecision } from '@/types'

export function PortalPage() {
  const text = useText()
  const navigate = useNavigate()
  const [search, setSearch] = useState('')
  const [category, setCategory] = useState('')
  const [view, setView] = useState<'all' | 'favorites'>('all')
  const compactCards = useAppStore((state) => state.portalCardSize === 'compact')
  const portal = useQuery({ queryKey: ['portal', 'bootstrap'], queryFn: getPortalBootstrap })
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

  return (
    <Page title={text.portal}>
      <div className="portal-toolbar">
        <div className="portal-toolbar-main">
          <Input
            allowClear
            onChange={(event) => setSearch(event.target.value)}
            placeholder={text.portalSearch}
            prefix={<SearchOutlined />}
            value={search}
          />
          <Segmented
            aria-label={text.portal}
            onChange={(value) => setView(value === 'favorites' ? 'favorites' : 'all')}
            options={[
              { label: text.portalApplications, value: 'all' },
              { icon: <StarOutlined />, label: text.portalFavorites, value: 'favorites' },
            ]}
            value={view}
          />
        </div>
        <div className="portal-categories" role="group" aria-label={text.portalCategory}>
          <Button onClick={() => setCategory('')} size="small" type={category ? 'text' : 'primary'}>{text.portalAll}</Button>
          {categories.map((item) => (
            <Button key={item} onClick={() => setCategory(item)} size="small" type={category === item ? 'primary' : 'text'}>{item}</Button>
          ))}
        </div>
      </div>

      <section aria-live="polite" className="portal-section">
        {applications.length ? (
          <PortalGrid
            applications={applications}
            actions={actions}
            compact={compactCards}
            onDetails={(id) => navigate(`/portal/applications/${encodeURIComponent(id)}`)}
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

function PortalGrid({ applications, actions, compact, onDetails }: {
  applications: IdentityApplication[]
  actions: ReturnType<typeof usePortalActions>
  compact: boolean
  onDetails: (id: string) => void
}) {
  const text = useText()
  const serverURL = useAppStore((state) => state.host?.serverUrl)
  return (
    <div className={`portal-grid${compact ? ' compact' : ''}`}>
      {applications.map((application) => (
        <article className={`portal-card${compact ? ' compact' : ''}`} key={application.id}>
          <header>
            <Avatar
              alt={application.name}
              icon={<AppstoreOutlined />}
              shape="square"
              size={compact ? 32 : 40}
              src={applicationImageURL(application.iconUrl, serverURL)}
            />
            <span><strong>{application.name}</strong><small>{applicationGroup(application) || '—'}</small></span>
            <Button
              aria-label={`${application.favorite ? text.portalUnfavorite : text.portalFavorite} ${application.name}`}
              icon={application.favorite ? <StarFilled /> : <StarOutlined />}
              loading={actions.favorite.isPending && actions.favorite.variables?.application.id === application.id}
              onClick={() => actions.favorite.mutate({ application, favorite: !application.favorite })}
              title={application.favorite ? text.portalUnfavorite : text.portalFavorite}
              type="text"
            />
          </header>
          {compact ? null : <p>{application.description || application.slug}</p>}
          {compact ? null : <div className="portal-card-tags">{application.tags?.map((tag) => <Tag key={tag}>{tag}</Tag>)}</div>}
          <footer>
            <Button icon={<InfoCircleOutlined />} onClick={() => onDetails(application.id)} size={compact ? 'small' : undefined}>{text.portalDetails}</Button>
            <Button
              icon={<LinkOutlined />}
              loading={actions.launch.isPending && actions.launch.variables?.id === application.id}
              onClick={() => actions.launch.mutate(application)}
              size={compact ? 'small' : undefined}
              type="primary"
            >
              {text.portalOpen}
            </Button>
          </footer>
        </article>
      ))}
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
