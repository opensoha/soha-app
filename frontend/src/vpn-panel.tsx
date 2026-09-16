import { useState } from 'react'
import { Alert, Button, Select, Space } from 'antd'
import { PoweroffOutlined, SafetyCertificateOutlined } from '@ant-design/icons'
import { useIsMutating, useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { createVPNIntent, getVPNConnectionOptions, getVPNCurrentConnection } from '@/api'
import { connectNetwork, disconnectNetwork, getNetworkStatus } from '@/native/host'
import { useAppStore } from '@/store'
import { useText } from '@/i18n'

export function ManagedVPNPanel() {
  const text = useText()
  const host = useAppStore(s => s.host)
  const user = useAppStore(s => s.session?.user.userId)
  const chinese = useAppStore(s => s.locale) === 'zh_CN'
  const label = (zh: string, en: string) => chinese ? zh : en
  const client = useQueryClient()
  const [profileId, setProfileId] = useState('')
  const [selection, setSelection] = useState('auto')
  const [switching, setSwitching] = useState(false)
  const setRecovery = useAppStore(s => s.setVPNRecovery)
  const connectingOperations = useIsMutating({mutationKey:["vpn-connect"]})
  const supported = host?.app.platform === 'windows' || host?.app.platform === 'darwin'
  const statusQuery = useQuery({ queryKey: ['network-status'], queryFn: getNetworkStatus, enabled: supported, retry: false, refetchInterval: 5000, refetchIntervalInBackground: false })
  const status = statusQuery.data
  const deviceId = status?.deviceId || host?.app.deviceId || ''
  const optionsQuery = useQuery({ queryKey: ['vpn-options', host?.serverUrl, user, deviceId], queryFn: () => getVPNConnectionOptions(deviceId), enabled: Boolean(user && deviceId), retry: false, refetchInterval: 60000, refetchIntervalInBackground: false })
  const profiles = optionsQuery.data || []
  const profile = profiles.find(p => p.profileId === profileId) || profiles[0]
  const current = useQuery({ queryKey: ['vpn-current', user, deviceId], queryFn: () => getVPNCurrentConnection(deviceId), enabled: Boolean(user && deviceId && status?.sessionId), retry: false, refetchInterval: 10000, refetchIntervalInBackground: false })
  const details = current.data?.sessionId === status?.sessionId ? current.data : null
  const active = Boolean(status?.sessionId || status?.state === "degraded" || status?.state === "connected")
  const connected = active && status?.state === 'connected'
  const operation = useMutation({
 mutationKey:["vpn-connect"],
    mutationFn: async ({ disconnect = false, automatic = false, targetProfile = profile?.profileId, targetSelection = selection }: { disconnect?: boolean; automatic?: boolean; targetProfile?: string; targetSelection?: string } = {}) => {
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
  const actual = profiles.flatMap(p => p.candidates).find(c => c.gatewayId === status?.gatewayId)
  const latency = (id: string) => {
    if (!status?.probeMeasuredAt || Date.now() - Date.parse(status.probeMeasuredAt) > 60000) return label('未测速 / 已过期', 'Unmeasured / stale')
    const samples = status.probeResults?.find(s => s.gatewayId === id)?.rttSamplesMs.slice().sort((a,b) => a-b)
    return samples?.length ? `${samples[Math.floor(samples.length / 2)].toFixed(0)} ms` : label('探测失败', 'Probe failed')
  }
  const number = (value?: number, unit = '') => value == null ? label('未采集', 'Not collected') : `${value.toLocaleString(undefined, { maximumFractionDigits: 1 })}${unit}`
  const phase = status?.phase === 'measuring' ? label('正在测速', 'Measuring') : status?.phase === 'selecting' ? label('正在选择入口', 'Selecting entrance') : text.networkConnecting
  return <div className="vpn-content">
    <div className="vpn-policy-summary"><SafetyCertificateOutlined aria-hidden /><strong>{profile?.name || text.networkVPNManaged}</strong></div>
    {profiles.length > 1 ? <Select aria-label={label('连接方案', 'Connection profile')} value={profile?.profileId} disabled={busy} onChange={id => { setProfileId(id); setSelection('auto') }} options={profiles.map(p => ({ value: p.profileId, label: p.name }))} /> : null}
    {profile ? <div className="vpn-entrance-picker"><label htmlFor="vpn-entrance">{label('接入点', 'Entrance')}</label><Select id="vpn-entrance" value={selection} disabled={busy || !profile.allowManualSelection} onChange={setSelection} options={[{ value: 'auto', label: `Auto · ${profile.selectionStrategy === 'latency' ? label('延迟优先','Latency first') : profile.selectionStrategy === 'provider' ? label('供应商优先','Provider first') : label('固定优先级','Priority')}` }, ...profile.candidates.map(c => ({ value: c.gatewayId, label: `${c.name} · ${c.providerName || c.providerCode} · ${latency(c.gatewayId)}${c.available ? '' : ` · ${c.reasonCode}`}`, disabled: !c.available }))]} /></div> : null}
    <div className="network-connect-control">
      <Button aria-label={active ? text.networkDisconnect : text.networkConnect} aria-pressed={connected} className="network-connect-button" disabled={!supported || busy || statusQuery.isError || (!active && !profile?.available)} icon={<PoweroffOutlined />} loading={operation.isPending || status?.state === 'connecting'} onClick={() => operation.mutate({ disconnect: active })} shape="circle" type={connected ? 'primary' : 'default'} />
      <strong aria-live="polite">{!supported ? text.networkVPNUnavailable : switching ? label('切换中', 'Switching') : busy ? phase : statusQuery.isPending || optionsQuery.isFetching ? text.checking : statusQuery.isError ? text.networkServiceUnavailable : connected ? text.networkConnected : !profile ? text.networkVPNWaitingPolicy : text.networkDisconnected}</strong>
      <span className="vpn-connect-hint">{text.networkVPNHelp}</span>
      {active && profile ? <Button disabled={busy} onClick={() => { setSwitching(true); operation.mutate({}) }}>{label('重新连接以切换', 'Reconnect to switch')}</Button> : null}
    </div>
    {!supported ? <Alert description={host?.app.platform === 'darwin' ? text.networkMacVPNPending : text.networkWindowsOnly} showIcon type="info" /> : null}
    {optionsQuery.isError || operation.isError ? <Alert showIcon type="error" description={(optionsQuery.error || operation.error)?.message} action={<Button onClick={() => optionsQuery.refetch()}>{text.retry}</Button>} /> : null}
    {status?.diagnostic ? <Alert showIcon type="warning" description={status.diagnostic} /> : null}
    {active ? <><Space orientation="vertical"><strong>{label('实际接入', 'Actual entrance')}: {actual?.name || details?.gatewayName || status?.gatewayId}</strong><span>{label('选择原因', 'Selection reason')}: {status?.selectionReason || details?.reasonCode || '—'}</span></Space><dl className="network-link-details" aria-label={text.networkStatus}>
      <div><dt>{text.networkMode}</dt><dd>{status?.mode === 'external_vpn_ztna' ? text.networkModeVPNZTNA : status?.mode === 'internal_ztna' ? text.networkModeInternalZTNA : status?.mode === 'external_direct_ztna' ? text.networkModeDirectZTNA : status?.mode === 'external_vpn' ? text.networkModeVPN : '—'}</dd></div>
      <div><dt>{label('隧道 IP', 'Tunnel IP')}</dt><dd>{status?.tunnelIP || details?.tunnelIP || '—'}</dd></div>
      <div><dt>{label('入口探测 RTT', 'Entrance probe RTT')}</dt><dd>{status?.gatewayId ? latency(status.gatewayId) : '—'}</dd></div>
      <div><dt>{label('本次时长', 'Duration')}</dt><dd>{status?.connectedAt ? `${Math.max(0, Math.floor((Date.now()-Date.parse(status.connectedAt))/1000))} s` : '—'}</dd></div>
      <div><dt>{label('上传 / 下载速率', 'Upload / download rate')}</dt><dd>{number(details?.uploadBytesPerSecond == null ? undefined : details.uploadBytesPerSecond / 1024, ' KiB/s')} / {number(details?.downloadBytesPerSecond == null ? undefined : details.downloadBytesPerSecond / 1024, ' KiB/s')}</dd></div>
      <div><dt>{label('本次传输量', 'Transferred')}</dt><dd>{number(details?.uploadBytes == null ? undefined : details.uploadBytes / 1048576, ' MiB')} / {number(details?.downloadBytes == null ? undefined : details.downloadBytes / 1048576, ' MiB')}</dd></div>
      <div><dt>{label('最后握手', 'Last handshake')}</dt><dd>{details?.lastHandshakeAt || label('未采集','Not collected')}</dd></div>
      <div><dt>{label('测量时间', 'Measured at')}</dt><dd>{details?.measuredAt || '—'}</dd></div>
    </dl></> : null}
  </div>
}
