import { useId, useState } from 'react'
import { Alert, Button, Modal, Radio, Select } from 'antd'
import { DownOutlined, LoadingOutlined, PoweroffOutlined } from '@ant-design/icons'
import { useIsMutating, useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { createVPNIntent, getVPNConnectionOptions, getVPNCurrentConnection } from '@/api'
import { connectNetwork, disconnectNetwork, getNetworkStatus } from '@/native/host'
import { useAppStore } from '@/store'
import { useText } from '@/i18n'

function LatencyIndicator({ reading }: { reading: { text: string; ms?: number } }) {
  const bars = reading.ms == null ? 0 : reading.ms <= 50 ? 3 : reading.ms <= 100 ? 2 : 1
  return (
    <span className="vpn-entrance-latency" data-bars={bars}>
      <svg aria-hidden="true" viewBox="0 0 14 14" width="14" height="14" fill="currentColor">
        <rect x="1" y="8" width="3" height="5" rx="1" opacity={bars >= 1 ? 1 : .25} />
        <rect x="6" y="5" width="3" height="8" rx="1" opacity={bars >= 2 ? 1 : .25} />
        <rect x="11" y="1" width="3" height="12" rx="1" opacity={bars >= 3 ? 1 : .25} />
      </svg>
      {reading.text}
    </span>
  )
}

export function ManagedVPNPanel() {
  const text = useText()
  const connectionStateId = useId()
  const host = useAppStore(s => s.host)
  const user = useAppStore(s => s.session?.user.userId)
  const chinese = useAppStore(s => s.locale) === 'zh_CN'
  const label = (zh: string, en: string) => chinese ? zh : en
  const client = useQueryClient()
  const [profileId, setProfileId] = useState('')
  const [selection, setSelection] = useState('auto')
  const [draft, setDraft] = useState<{ profileId: string; selection: string } | null>(null)
  const [switching, setSwitching] = useState(false)
  const setRecovery = useAppStore(s => s.setVPNRecovery)
  const connectingOperations = useIsMutating({mutationKey:["vpn-connect"]})
  const supported = host?.app.platform === 'windows' || host?.app.platform === 'darwin'
  const statusQuery = useQuery({ queryKey: ['network-status'], queryFn: getNetworkStatus, enabled: supported, retry: false, refetchInterval: 5000, refetchIntervalInBackground: false })
  const status = statusQuery.data
  const deviceId = status?.deviceId || host?.app.deviceId || ''
  const optionsQuery = useQuery({ queryKey: ['vpn-options', host?.serverUrl, user, deviceId], queryFn: () => getVPNConnectionOptions(deviceId), enabled: Boolean(user && deviceId), retry: false, refetchInterval: 60000, refetchIntervalInBackground: false })
  const current = useQuery({ queryKey: ['vpn-current', user, deviceId], queryFn: () => getVPNCurrentConnection(deviceId), enabled: Boolean(user && deviceId && status?.sessionId), retry: false, refetchInterval: 10000, refetchIntervalInBackground: false })
  const details = current.data?.sessionId === status?.sessionId ? current.data : null
  const active = Boolean(status?.sessionId)
  const activeProfileId = active ? status?.profileId || details?.profileId : undefined
  const profiles = optionsQuery.data || []
  const activeProfile = profiles.find(p => p.profileId === activeProfileId)
  const profile = profiles.find(p => p.profileId === profileId) ?? activeProfile ?? (active ? undefined : profiles[0])
  const draftSelection = draft && draft.profileId === profile?.profileId ? draft.selection : null
  const allowedEntrance = (id: string) => profile?.allowManualSelection && profile.candidates.some(c => c.available && c.gatewayId === id) ? id : 'auto'
  const entrance = allowedEntrance(selection)
  const needsCleanup = active || status?.state === 'degraded'
  const connected = active && status?.state === 'connected'
  const operation = useMutation({
    mutationKey: ['vpn-connect'],
    mutationFn: async ({ disconnect = false, automatic = false, targetProfile = profile?.profileId, targetSelection = entrance }: { disconnect?: boolean; automatic?: boolean; targetProfile?: string; targetSelection?: string } = {}) => {
      if (!automatic) setRecovery(null)
      if (disconnect || active || status?.state === 'degraded') {
        const cleared = await disconnectNetwork()
        client.setQueryData(['network-status'], cleared)
        if (cleared.state !== 'disconnected') throw new Error(label('旧连接尚未清理完成', 'Previous connection cleanup is incomplete'))
        if (disconnect) return cleared
      }
      if (!profile || !targetProfile || !deviceId) throw new Error(text.networkVPNWaitingPolicy)
      const intent = await createVPNIntent({ deviceId, profileId: targetProfile, selection: targetSelection === 'auto' ? 'auto' : 'manual', ...(targetSelection === 'auto' ? {} : { gatewayId: targetSelection }) })
      const result = await connectNetwork({ intentId: intent.intentId, intentToken: intent.token, requestId: crypto.randomUUID() })
      if (result.failoverOnDisconnect && !automatic) setRecovery({ profileId: targetProfile, selection: targetSelection || 'auto', max: result.maxAttempts || 1, cooldown: Math.max(5, result.retryCooldownSeconds || 30), failures: 0, attempts: 0, nextAt: 0 })
      return result
    },
    onSuccess: result => client.setQueryData(['network-status'], result),
    onSettled: () => { setSwitching(false); void client.invalidateQueries({ queryKey: ['network-status'] }); void client.invalidateQueries({ queryKey: ['vpn-current'] }) },
  })
  const busy = connectingOperations > 0 || operation.isPending || status?.state === 'connecting'
  const actual = activeProfile?.candidates.find(c => c.gatewayId === status?.gatewayId)
  const activeServer = connected ? actual?.name || details?.gatewayName || status?.gatewayId : undefined
  const editingActiveProfile = connected && Boolean(activeProfileId) && activeProfileId === profile?.profileId
  const serverSelection = editingActiveProfile
    ? allowedEntrance(status?.selection === 'manual' ? status.gatewayId || 'auto' : 'auto')
    : entrance
  const serverLabel = (editingActiveProfile && activeServer) || profile?.candidates.find(c => c.gatewayId === serverSelection)?.name || label('自动', 'Automatic')
  const serverField = connected && !editingActiveProfile ? label('目标服务器', 'Target server') : label('当前服务器', 'Current server')
  const canConnect = supported && !busy && statusQuery.isSuccess && Boolean(profile?.available)
  const latency = (id: string): { text: string; ms?: number } => {
    const measuredAt = status?.probeMeasuredAt ? Date.parse(status.probeMeasuredAt) : NaN
    if (!Number.isFinite(measuredAt)) return { text: label('未测速', 'Not measured') }
    if (Date.now() - measuredAt > 60000) return { text: label('已过期', 'Stale') }
    const result = status?.probeResults?.find(sample => sample.gatewayId === id)
    if (!result) return { text: label('未测速', 'Not measured') }
    const samples = result.rttSamplesMs.filter(value => Number.isFinite(value) && value >= 0).sort((a, b) => a - b)
    const ms = samples[Math.floor(samples.length / 2)]
    return ms == null ? { text: label('探测失败', 'Probe failed') } : { ms, text: `${ms.toFixed(0)} ms` }
  }
  const candidates = profile?.candidates.map(candidate => ({
    ...candidate,
    reading: candidate.available ? latency(candidate.gatewayId) : { text: label('不可用', 'Unavailable') },
  })) ?? []
  const fastest = profile?.selectionStrategy === 'latency'
    ? candidates.reduce<{ text: string; ms?: number } | undefined>((best, { reading }) =>
      reading.ms != null && (best?.ms == null || reading.ms < best.ms) ? reading : best, undefined)
    : undefined
  const autoPolicy = profile?.selectionStrategy === 'latency' ? label('延迟优先', 'Latency first')
    : profile?.selectionStrategy === 'provider' ? label('供应商优先', 'Provider first') : label('固定优先级', 'Priority')
  const number = (value?: number, unit = '') => value == null ? label('未采集', 'Not collected') : `${value.toLocaleString(undefined, { maximumFractionDigits: 1 })}${unit}`
  const phase = status?.phase === 'measuring' ? label('正在测速', 'Measuring') : status?.phase === 'selecting' ? label('正在选择入口', 'Selecting entrance') : text.networkConnecting
  const connectionState = !supported ? text.networkVPNUnavailable
    : switching ? label('切换中', 'Switching')
    : busy ? phase
    : statusQuery.isPending || optionsQuery.isFetching ? text.checking
    : statusQuery.isError ? text.networkServiceUnavailable
    : connected ? text.networkConnected
    : !profile ? text.networkVPNWaitingPolicy : text.networkDisconnected
  const connectionAction = needsCleanup ? text.networkDisconnect : text.networkConnect
  const canToggleConnection = needsCleanup ? supported && !busy && !statusQuery.isError : canConnect
  return <div className="vpn-content">
    <div className="network-connect-control">
      <Button
        aria-label={connectionAction}
        aria-describedby={connectionStateId}
        aria-busy={busy}
        className="network-connect-button"
        data-connected={connected}
        disabled={!canToggleConnection}
        onClick={() => operation.mutate({ disconnect: needsCleanup })}
        type="text"
      >
        <span className="vpn-power-face">
          <span className="vpn-power-icon" aria-hidden="true">{busy ? <LoadingOutlined spin /> : <PoweroffOutlined />}</span>
          <span>{canToggleConnection ? connectionAction : connectionState}</span>
        </span>
      </Button>
      <span id={connectionStateId} className="visually-hidden" role="status">{connectionState}</span>
      {profiles.length > 1 || (!profile && profiles.length > 0) ? <Select className="vpn-profile-select" aria-label={label('连接方案', 'Connection profile')} value={profile?.profileId} disabled={busy} onChange={id => { setProfileId(id); setSelection('auto'); setDraft(null) }} options={profiles.map(p => ({ value: p.profileId, label: p.name }))} /> : null}
      {activeServer && !editingActiveProfile ? <span className="vpn-connect-hint">{label('当前服务器', 'Current server')} · {activeServer}</span> : null}
      {profile ? (
        <div className="vpn-current-server">
          <span>{serverField}</span>
          <Button type="text" aria-label={`${serverField} · ${serverLabel}`} aria-haspopup="dialog" disabled={busy} onClick={() => setDraft({ profileId: profile.profileId, selection: serverSelection })}>
            {serverSelection === 'auto' ? <span className="vpn-auto-badge">AUTO</span> : null}
            <span>{serverLabel}</span>
            <DownOutlined aria-hidden="true" />
          </Button>
        </div>
      ) : null}
    </div>
    {profile ? (
      <Modal
        title={label('选择服务器节点', 'Choose a VPN server')}
        open={draftSelection !== null}
        destroyOnHidden
        width={520}
        onCancel={() => setDraft(null)}
        cancelText={text.cancel}
        okText={active ? label('确认切换', 'Confirm switch') : label('确认连接', 'Connect')}
        okButtonProps={{ disabled: !canConnect || draftSelection !== allowedEntrance(draftSelection ?? 'auto') }}
        onOk={() => {
          if (!canConnect || draftSelection === null || draftSelection !== allowedEntrance(draftSelection)) return
          setSelection(draftSelection)
          setDraft(null)
          setSwitching(active)
          operation.mutate({ targetProfile: profile.profileId, targetSelection: draftSelection })
        }}
      >
        <div className="vpn-entrance-heading">
          <span>{label('接入点', 'Access point')}</span>
          <span>{status?.demo ? label('模拟延迟', 'Simulated latency') : label('延迟', 'Latency')}</span>
        </div>
        <Radio.Group className="vpn-entrance-options" aria-label={label('接入点', 'Access point')} value={draftSelection} disabled={busy || !profile.available} onChange={event => setDraft({ profileId: profile.profileId, selection: event.target.value })}>
          <Radio value="auto">
            <span><span className="vpn-auto-badge">AUTO</span> {label('自动', 'Automatic')} <small>{autoPolicy}</small></span>
            {fastest ? <LatencyIndicator reading={fastest} /> : null}
          </Radio>
          {candidates.map(candidate => (
            <Radio key={candidate.gatewayId} value={candidate.gatewayId} disabled={!profile.allowManualSelection || !candidate.available}>
              <span>{candidate.name} <small>{candidate.providerName || candidate.providerCode}</small></span>
              <LatencyIndicator reading={candidate.reading} />
            </Radio>
          ))}
        </Radio.Group>
      </Modal>
    ) : null}
    <span className="vpn-connect-hint">{profile?.name || text.networkVPNManaged}</span>
    {!supported ? <Alert description={host?.app.platform === 'darwin' ? text.networkMacVPNPending : text.networkWindowsOnly} showIcon type="info" /> : null}
    {optionsQuery.isError || operation.isError ? <Alert showIcon type="error" description={(optionsQuery.error || operation.error)?.message} action={<Button onClick={() => optionsQuery.refetch()}>{text.retry}</Button>} /> : null}
    {status?.diagnostic ? <Alert showIcon type="warning" description={status.diagnostic} /> : null}
    {active ? <dl className="network-link-details" aria-label={text.networkStatus}>
      <div><dt>{label('隧道 IP', 'Tunnel IP')}</dt><dd>{status?.tunnelIP || details?.tunnelIP || '—'}</dd></div>
      <div><dt>{label('本次时长', 'Duration')}</dt><dd>{status?.connectedAt ? `${Math.max(0, Math.floor((Date.now()-Date.parse(status.connectedAt))/1000))} s` : '—'}</dd></div>
      <div><dt>{label('上传 / 下载速率', 'Upload / download rate')}</dt><dd>{number(details?.uploadBytesPerSecond == null ? undefined : details.uploadBytesPerSecond / 1024, ' KiB/s')} / {number(details?.downloadBytesPerSecond == null ? undefined : details.downloadBytesPerSecond / 1024, ' KiB/s')}</dd></div>
    </dl> : null}
  </div>
}
