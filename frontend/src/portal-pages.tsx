import { useMemo, useState, type ReactNode } from 'react'
import {
  AppstoreOutlined,
  ArrowLeftOutlined,
  InfoCircleOutlined,
  LinkOutlined,
  SearchOutlined,
  StarFilled,
  StarOutlined,
} from '@ant-design/icons'
import { Alert, App, Avatar, Button, Descriptions, Empty, Input, Skeleton, Tag } from 'antd'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useNavigate, useParams } from 'react-router-dom'
import {
  getPortalApplication,
  getPortalBootstrap,
  launchPortalApplication,
  setPortalFavorite,
} from '@/api'
import { useText } from '@/i18n'
import { openBrowserURL } from '@/native/host'
import { Page } from '@/pages'
import { useAppStore } from '@/store'
import type { IdentityApplication, PortalLaunchDecision } from '@/types'

export function PortalPage() {
  const text = useText()
  const navigate = useNavigate()
  const [search, setSearch] = useState('')
  const [category, setCategory] = useState('')
  const portal = useQuery({ queryKey: ['portal', 'bootstrap'], queryFn: getPortalBootstrap })
  const actions = usePortalActions()
  const applications = useMemo(() => {
    const needle = search.trim().toLocaleLowerCase()
    return (portal.data?.applications || []).filter((application) => {
      if (category && application.category !== category) return false
      if (!needle) return true
      return [application.name, application.slug, application.description, application.category, application.providerType, ...(application.tags || [])]
        .some((value) => value?.toLocaleLowerCase().includes(needle))
    })
  }, [category, portal.data?.applications, search])

  if (portal.isLoading) {
    return <Page description={text.portalDescription} title={text.portal}><Skeleton active paragraph={{ rows: 8 }} /></Page>
  }
  if (portal.isError || !portal.data) {
    return (
      <Page description={text.portalDescription} title={text.portal}>
        <Alert
          action={<Button onClick={() => void portal.refetch()} size="small">{text.retry}</Button>}
          description={errorMessage(portal.error)}
          showIcon
          title={text.portalEmpty}
          type="warning"
        />
      </Page>
    )
  }

  return (
    <Page description={text.portalDescription} title={text.portal}>
      <div className="portal-toolbar">
        <Input
          allowClear
          onChange={(event) => setSearch(event.target.value)}
          placeholder={text.portalSearch}
          prefix={<SearchOutlined />}
          value={search}
        />
        <div className="portal-categories" role="group" aria-label={text.portalCategory}>
          <Button onClick={() => setCategory('')} size="small" type={category ? 'text' : 'primary'}>{text.portalAll}</Button>
          {portal.data.categories.map((item) => (
            <Button key={item} onClick={() => setCategory(item)} size="small" type={category === item ? 'primary' : 'text'}>{item}</Button>
          ))}
        </div>
      </div>

      <PortalSection title={text.portalFavorites}>
        {portal.data.favorites.length ? (
          <PortalGrid
            applications={portal.data.favorites}
            actions={actions}
            onDetails={(id) => navigate(`/portal/applications/${encodeURIComponent(id)}`)}
          />
        ) : <Empty description={text.portalEmpty} image={Empty.PRESENTED_IMAGE_SIMPLE} />}
      </PortalSection>

      <PortalSection title={text.portalApplications}>
        {applications.length ? (
          <PortalGrid
            applications={applications}
            actions={actions}
            onDetails={(id) => navigate(`/portal/applications/${encodeURIComponent(id)}`)}
          />
        ) : <Empty description={search || category ? text.portalNoMatches : text.portalEmpty} image={Empty.PRESENTED_IMAGE_SIMPLE} />}
      </PortalSection>

      <div className="portal-summary-grid">
        <PortalSection title={text.portalRecent}>
          {portal.data.recent.length ? (
            <div className="portal-recent-list">
              {portal.data.recent.map((launch) => (
                <button key={launch.id} onClick={() => navigate(`/portal/applications/${encodeURIComponent(launch.applicationId)}`)} type="button">
                  <span>{launch.applicationName || launch.applicationId}</span>
                  <small>{launch.providerType}</small>
                </button>
              ))}
            </div>
          ) : <Empty description={text.portalEmpty} image={Empty.PRESENTED_IMAGE_SIMPLE} />}
        </PortalSection>
        <PortalSection title={text.portalSecurity}>
          <Descriptions
            column={1}
            items={[
              { key: 'mfa', label: text.portalMfa, children: portal.data.security.mfaEnabled ? 'Enabled' : '—' },
              { key: 'sessions', label: text.portalSessions, children: portal.data.security.activeSession },
              { key: 'sources', label: text.identities, children: portal.data.security.linkedSources.join(', ') || '—' },
            ]}
            size="small"
          />
        </PortalSection>
      </div>
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

  if (application.isLoading) {
    return <Page description={text.portalDescription} title={text.portal}><Skeleton active paragraph={{ rows: 6 }} /></Page>
  }
  if (application.isError || !application.data) {
    return (
      <Page description={text.portalDescription} title={text.portal}>
        <Alert
          action={<Button onClick={() => void application.refetch()} size="small">{text.retry}</Button>}
          description={errorMessage(application.error)}
          showIcon
          title={text.portalEmpty}
          type="warning"
        />
      </Page>
    )
  }

  const item = application.data
  return (
    <Page description={item.description || text.portalDescription} title={item.name}>
      <Button icon={<ArrowLeftOutlined />} onClick={() => navigate('/portal')} type="link">{text.portalBack}</Button>
      <div className="portal-detail">
        <Avatar icon={<AppstoreOutlined />} shape="square" size={64} src={item.iconUrl} />
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

function PortalSection({ title, children }: { title: string; children: ReactNode }) {
  return <section className="portal-section"><h2>{title}</h2>{children}</section>
}

function PortalGrid({ applications, actions, onDetails }: {
  applications: IdentityApplication[]
  actions: ReturnType<typeof usePortalActions>
  onDetails: (id: string) => void
}) {
  const text = useText()
  return (
    <div className="portal-grid">
      {applications.map((application) => (
        <article className="portal-card" key={application.id}>
          <header>
            <Avatar icon={<AppstoreOutlined />} shape="square" size={40} src={application.iconUrl} />
            <span><strong>{application.name}</strong><small>{application.category || application.providerType || '—'}</small></span>
            <Button
              aria-label={`${application.favorite ? text.portalUnfavorite : text.portalFavorite} ${application.name}`}
              icon={application.favorite ? <StarFilled /> : <StarOutlined />}
              loading={actions.favorite.isPending && actions.favorite.variables?.application.id === application.id}
              onClick={() => actions.favorite.mutate({ application, favorite: !application.favorite })}
              title={application.favorite ? text.portalUnfavorite : text.portalFavorite}
              type="text"
            />
          </header>
          <p>{application.description || application.slug}</p>
          <div className="portal-card-tags">{application.tags?.map((tag) => <Tag key={tag}>{tag}</Tag>)}</div>
          <footer>
            <Button icon={<InfoCircleOutlined />} onClick={() => onDetails(application.id)}>{text.portalDetails}</Button>
            <Button
              icon={<LinkOutlined />}
              loading={actions.launch.isPending && actions.launch.variables?.id === application.id}
              onClick={() => actions.launch.mutate(application)}
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
