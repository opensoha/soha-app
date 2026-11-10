import { useState } from 'react'
import { ArrowDownOutlined, ArrowUpOutlined, BranchesOutlined, PlayCircleOutlined, PoweroffOutlined, ReloadOutlined } from '@ant-design/icons'
import { Alert, Button, Descriptions, Empty, Input, Popconfirm, Radio, Skeleton, Space, Tabs, Tag } from 'antd'
import { useQuery } from '@tanstack/react-query'
import { proxyAction, proxyRules, proxyStatus } from '@/native/host'
import { useAppStore } from '@/store'
import type { ProxyAction, ProxyRule, ProxyWorkbench } from '@/types'
import { PersonalRules } from './rules'
import { InterceptionPanel } from './interception'
import './workbench.css'

export function ProxyWorkbenchPanel() {
 const server = useAppStore(s => s.host?.serverUrl)
 const user = useAppStore(s => s.session?.user.userId)
 const zh = useAppStore(s => s.locale) === 'zh_CN'
 const t = (a: string, b: string) => zh ? a : b
 const query = useQuery({
  queryKey: ['proxy-workbench', server, user],
  queryFn: proxyStatus,
  retry: false,
  refetchInterval: query => query.state.data?.process.state === 'running' ? 3_000 : 10_000,
  refetchIntervalInBackground: false,
 })
 return <section className="page proxy-workbench">
  <h1 className="visually-hidden">{t('本机代理','Local proxy')}</h1>
  {query.isError && <Alert
   type="warning"
   showIcon
   title={t('无法读取本机代理状态。','Unable to read local proxy status.')}
   action={<Button icon={<ReloadOutlined />} loading={query.isFetching} onClick={() => void query.refetch()}>{t('重试','Retry')}</Button>}
  />}
  {query.isPending ? <Skeleton active paragraph={{rows: 6}} /> : query.data && <Workbench
   key={JSON.stringify([server,user,query.data.profileId])}
   data={query.data}
   readFailed={query.isError}
   refresh={async () => {await query.refetch()}}
   t={t}
  />}
  <details className="proxy-disclosure">
   <summary>{t('网络接管','Network takeover')}</summary>
   <InterceptionPanel key={JSON.stringify([server,user])} scopeKey={JSON.stringify([server,user])} t={t}/>
  </details>
 </section>
}
function Workbench({data:d,readFailed,refresh,t}:{data:ProxyWorkbench;readFailed:boolean;refresh:()=>Promise<void>;t:(a:string,b:string)=>string}) {
 const [busy,setBusy] = useState<ProxyAction['kind']>()
 const [feedback,setFeedback] = useState<{text:string; failed?:boolean}>()
 const [probeProfile,setProbeProfile] = useState('')
 const enabled = (name:string) => !readFailed && d.capabilities?.some(c => c.name === name && c.state === 'available')
 const running = d.process.state === 'running'
 const stopped = d.process.state === 'stopped'
 const controllable = enabled('process_control') && d.process.ownership === 'soha_owned'
 const stateLabel = readFailed ? t('观测已过期','Observation stale') :
  running ? t('运行中','Running') : stopped ? t('已停止','Stopped') : t('等待状态确认','Awaiting state')
 const sampleKnown = !readFailed && running && d.traffic.state === 'fresh' && d.traffic.processEpoch === d.process.processEpoch
 const totalsKnown = !readFailed && running && d.traffic.state !== 'unavailable' && d.traffic.processEpoch === d.process.processEpoch
 const groups = d.groups || []
 const simulated = d.diagnostics?.some(item => item.code === 'demo_simulation')
 async function act(input:ProxyAction) {
  setBusy(input.kind)
  setFeedback(undefined)
  try {
   const result = await proxyAction(input)
   if (input.kind === 'close') {
    const sameProcess = result.connections.processEpoch === input.processEpoch
    const remains = result.connections.items?.some(c => c.connectionId === input.connectionId)
    setFeedback({text:!sameProcess ? t('进程已变化，请重新核对连接状态。','Process changed. Review the latest connections.') : remains ? t('请求已返回，连接仍在观察列表中。','Request returned; the connection is still observed.') : t('最新观察中已无此连接；也可能已自然结束。','Connection is absent from the latest observation; it may also have ended naturally.')})
   }
   await refresh()
  } catch {
   setFeedback({text:t('操作未完成，请刷新状态后重试。','Operation failed. Refresh and retry.'),failed:true})
   await refresh()
  } finally {
   setBusy(undefined)
  }
 }
 const control = (kind:ProxyAction['kind'],label:string,name='process_control') => <Button key={kind} loading={busy === kind} disabled={Boolean(busy) || !enabled(name) || name === 'process_control' && !controllable} onClick={() => void act({kind})}>{label}</Button>
 const ruleView = (rules:ProxyRule[]) => rules.length ? <ol>{rules.map(r=><li key={r.ruleId}><Tag>{r.source}</Tag>{r.matcher.type}: {r.matcher.value || '*'} → {r.action.type} {r.action.targetId} {!r.enabled && t('（已禁用）',' (disabled)')}</li>)}</ol> : <Empty />
 return <>
 {feedback && <Alert showIcon type={feedback.failed ? 'warning' : 'info'} title={feedback.text}/>}
 <section className="proxy-panel" aria-label="Mihomo">
  <header className="proxy-runtime">
   <div className="proxy-runtime-mark"><BranchesOutlined /></div>
   <div className="proxy-runtime-name"><h2>Mihomo</h2><p>{simulated ? t('模拟进程与流量','Simulated process and traffic') : d.process.ownership === 'soha_owned' ? t('Soha 管理的本机进程','Soha-managed local process') : t('外部管理的进程','Externally managed process')}</p></div>
   <Tag color={!readFailed && running ? 'success' : 'default'}>{stateLabel}</Tag>
   <Space wrap>
    <Button type="primary" icon={<PlayCircleOutlined />} loading={busy === 'start'} disabled={Boolean(busy) || !controllable || !stopped} onClick={() => void act({kind:'start'})}>{t('开启','Start')}</Button>
    <Popconfirm title={t('停止 Mihomo？','Stop Mihomo?')} description={t('当前代理连接可能中断。','Active proxy connections may be interrupted.')} onConfirm={() => act({kind:'stop'})} disabled={!controllable || !running || Boolean(busy)}>
     <Button icon={<PoweroffOutlined />} loading={busy === 'stop'} disabled={Boolean(busy) || !controllable || !running}>{t('关闭','Stop')}</Button>
    </Popconfirm>
   </Space>
  </header>
  <div className="proxy-traffic" aria-label={t('Mihomo 流量','Mihomo traffic')}>
   <TrafficMetric icon={<ArrowUpOutlined />} label={t('上传速率','Upload rate')} rate={sampleKnown ? d.traffic.uploadBytesPerSecond : null} total={totalsKnown ? d.traffic.uploadTotal : null} totalLabel={t('累计上传','Total upload')}/>
   <TrafficMetric icon={<ArrowDownOutlined />} label={t('下载速率','Download rate')} rate={sampleKnown ? d.traffic.downloadBytesPerSecond : null} total={totalsKnown ? d.traffic.downloadTotal : null} totalLabel={t('累计下载','Total download')}/>
   <div className="proxy-traffic-metric"><span>{t('活动连接','Active connections')}</span><strong>{!readFailed && running && d.connections.processEpoch === d.process.processEpoch ? d.connections.totalActive : '—'}</strong><small>{sampleKnown ? t('本次进程观测','Current process sample') : t('暂无可用采样','No sample available')}</small></div>
  </div>
 </section>
 {d.deliveryMode === 'direct_subscription' && <Alert type="warning" showIcon title={t('直接连接：本机会接收必要上游信息。发布方式不会自动切换。','Direct connection: this device receives necessary upstream information. Delivery mode never changes automatically.')}/>}
 <section className="proxy-panel proxy-nodes">
  <h2>{t('节点选择','Node selection')}</h2>
  <p>{running ? t('选择此策略组使用的节点。','Choose a node for this policy group.') : t('开启 Mihomo 后可切换节点。','Start Mihomo to switch nodes.')}</p>
  {groups.length ? groups.map(group => <div className="proxy-node-group" key={group.groupId}>
   <strong>{group.label}</strong>
   <Radio.Group
    aria-label={group.label}
    className="proxy-node-options"
    disabled={Boolean(busy) || !running || !enabled('select') || group.type !== 'select'}
    value={group.selectedNodeId}
    onChange={event=>void act({kind:'select',groupId:group.groupId,nodeId:event.target.value})}
   >
    {group.nodeIds.map(id=><Radio key={id} value={id}>{d.nodes.find(node => node.nodeId === id)?.label || id}</Radio>)}
   </Radio.Group>
  </div>) : <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={t('暂无可选节点','No nodes available')}/>}
 </section>
 <details className="proxy-disclosure">
 <summary>{t('进程详情、规则与诊断','Process details, rules and diagnostics')}</summary>
 <Descriptions column={2} items={[{key:'service',label:t('服务','Service'),children:d.state},{key:'config',label:t('配置版本','Configuration'),children:d.revision},{key:'mode',label:t('发布方式','Delivery'),children:d.deliveryMode === 'mapped_nodes' ? t('内网逐节点映射','Mapped internal nodes') : d.deliveryMode === 'gateway' ? t('聚合网关','Gateway') : d.deliveryMode === 'direct_subscription' ? t('直接连接','Direct subscription') : t('未知','Unknown')}]} />
 <Space wrap>{control('restart',t('重启','Restart'))}{control('repair',t('恢复','Repair'))}{control('refresh_subscription',t('主动更新订阅','Update subscription'),'subscription_refresh')}</Space>
 <Tabs items={[
 {key:'probe',label:t('节点测速','Node probes'),children:<><Input aria-label={t('管理员批准的测速方案编号','Approved probe profile')} value={probeProfile} onChange={e=>setProbeProfile(e.target.value)} placeholder={t('管理员批准的测速方案编号','Administrator-approved probe profile')}/>{(d.nodes || []).map(n=><p key={n.nodeId}>{n.label} <Button disabled={Boolean(busy) || !enabled('probe') || !probeProfile.trim()} onClick={()=>void act({kind:'probe',nodeId:n.nodeId,probeProfileId:probeProfile.trim()})}>{t('测速','Probe')}</Button>{d.probe?.nodeId===n.nodeId && ` ${d.probe.latencyMilliseconds} ms`}</p>)}</>},
 {key:'rules',label:t('我的规则','My rules'),children:<PersonalRules data={d} disabled={Boolean(busy) || !enabled('rules')} save={async input=>{const result = await proxyRules(input);await refresh();return result}} t={t}/>},
 {key:'effective',label:t('组织与生效规则','Organization & effective rules'),children:<><p>{t('平台保护 / 组织强制 → 我的规则 → 组织默认 → 兜底。组织规则只读。','Protection / required organization → personal → organization default → fallback. Organization rules are read-only.')}</p>{ruleView(d.rules.effectiveRules || [])}{(d.rules.conflicts || []).map(c=><Alert key={c.ruleId} type="warning" title={`${c.ruleId}: ${c.reasonCode} (${c.blockingRuleId})`}/>)}<h4>{t('被屏蔽规则','Masked rules')}</h4>{ruleView(d.maskedRules || [])}</>},
 {key:'traffic',label:t('连接详情','Connection details'),children:<><p>{d.connections.returnedCount} / {d.connections.totalActive} {d.connections.truncated && t('（已截断）',' (truncated)')}</p>{(d.connections.items || []).map(c=><p key={c.connectionId}>{c.destination || c.network || t('连接','Connection')} · ↑ {formatTransfer(c.upload)} ↓ {formatTransfer(c.download)} <Popconfirm title={t('关闭此连接？将影响当前传输。','Close this connection and interrupt its transfer?')} onConfirm={()=>act({kind:'close',connectionId:c.connectionId,processEpoch:d.connections.processEpoch})}><Button disabled={Boolean(busy) || !enabled('close_connection')}>{t('关闭此连接','Close connection')}</Button></Popconfirm></p>)}</>},
 {key:'diagnostics',label:t('DNS、日志与诊断','DNS, logs & diagnostics'),children:<>{(d.diagnostics || []).map(x=><p key={x.code}>{x.state}: {x.message}</p>)}{(d.dns || []).map(x=><p key={x.name}>{x.name}: {x.addresses.join(', ')} · {x.expiresAt}</p>)}<pre style={{whiteSpace:'pre-wrap'}}>{(d.logs || []).map(x=>`${x.occurredAt} ${x.level} ${x.message}`).join('\n')}</pre><details><summary>{t('高级诊断 / 可用功能','Advanced / capabilities')}</summary><p>PID: {d.process.pid ?? '—'}</p>{(d.capabilities || []).map(c=><p key={c.name}>{c.name}: {c.state} {c.reasonCode}</p>)}</details></>}
 ]}/></details></>
}

function TrafficMetric({icon,label,rate,total,totalLabel}:{icon:React.ReactNode;label:string;rate:number|null;total:number|null;totalLabel:string}) {
 return <div className="proxy-traffic-metric">
  <span>{icon} {label}</span>
  <strong>{formatTransfer(rate, '/s')}</strong>
  <small>{totalLabel} {formatTransfer(total)}</small>
 </div>
}

function formatTransfer(bytes:number|null, suffix='') {
 if (bytes === null || !Number.isFinite(bytes) || bytes < 0) return '—'
 const units = ['B','KiB','MiB','GiB','TiB']
 const power = bytes ? Math.min(units.length - 1, Math.max(0, Math.floor(Math.log2(bytes) / 10))) : 0
 return `${(bytes / 1024 ** power).toLocaleString(undefined, {maximumFractionDigits:power ? 1 : 0})} ${units[power]}${suffix}`
}
