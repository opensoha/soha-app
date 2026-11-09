import { useState } from 'react'
import { Alert, Button, Descriptions, Empty, Input, Popconfirm, Select, Space, Spin, Tabs, Tag } from 'antd'
import { useQuery } from '@tanstack/react-query'
import { proxyAction, proxyRules, proxyStatus } from '@/native/host'
import { useAppStore } from '@/store'
import type { ProxyAction, ProxyRule, ProxyWorkbench } from '@/types'
import { PersonalRules } from './rules'
import { InterceptionPanel } from './interception'

export function ProxyWorkbenchPanel() {
 const server = useAppStore(s => s.host?.serverUrl)
 const user = useAppStore(s => s.session?.user.userId)
 const zh = useAppStore(s => s.locale) === 'zh_CN'
 const t = (a: string, b: string) => zh ? a : b
 const query = useQuery({queryKey:['proxy-workbench',server,user],queryFn:proxyStatus,retry:false,refetchInterval:10000,refetchIntervalInBackground:false})
 return <section className="settings-section"><h2>{t('本机代理','Local proxy')}</h2><p>{t('此页面管理本机代理；站点代理由管理员管理。系统代理和 TUN 不会在此自动开启。','Manage this device. Site proxies are managed by administrators. System proxy and TUN are not enabled automatically.')}</p>
 <InterceptionPanel key={`${server}:${user}`} scopeKey={`${server}:${user}`} t={t}/>
 <Button loading={query.isFetching} onClick={() => void query.refetch()}>{t('只读刷新','Refresh status')}</Button>
 {query.isError && <Alert type="warning" showIcon title={t('本机代理服务不可用，请检查服务后重试。','Local proxy service unavailable. Check the service and retry.')} />}
 {query.isPending ? <Spin /> : query.data ? <Workbench key={`${server}:${user}:${query.data.profileId}`} data={query.data} refresh={async () => {await query.refetch()}} t={t}/> : <Empty />}</section>
}
function Workbench({data:d,refresh,t}:{data:ProxyWorkbench;refresh:()=>Promise<void>;t:(a:string,b:string)=>string}) {
 const [busy,setBusy] = useState(false)
 const [feedback,setFeedback] = useState('')
 const [probeProfile,setProbeProfile] = useState('')
 const cap = (name:string) => d.capabilities?.find(c => c.name === name)
 const enabled = (name:string) => cap(name)?.state === 'available'
 async function act(input:ProxyAction) {
  setBusy(true); setFeedback('')
  try {
   const result = await proxyAction(input)
   if (input.kind === 'close') {
    const sameProcess = result.connections.processEpoch === input.processEpoch
    const remains = result.connections.items?.some(c => c.connectionId === input.connectionId)
    setFeedback(!sameProcess ? t('进程已变化，请重新核对连接状态。','Process changed. Review the latest connections.') : remains ? t('请求已返回，连接仍在观察列表中。','Request returned; the connection is still observed.') : t('最新观察中已无此连接；也可能已自然结束。','Connection is absent from the latest observation; it may also have ended naturally.'))
   } else setFeedback(t('操作返回，已重新读取本机状态。请核对下方实际状态。','Operation returned. Review the observed state below.'))
   await refresh()
  }
  catch {setFeedback(t('操作未完成，请刷新状态后重试；配置和规则草稿保留。','Operation failed. Refresh and retry; drafts are retained.')); await refresh()}
  finally {setBusy(false)}
 }
 const control = (kind:ProxyAction['kind'],label:string,name='process_control') => <Button key={kind} loading={busy} disabled={busy || !enabled(name)} title={name === 'process_control' && d.process.ownership === 'external' ? t('此进程由其他程序管理，无法在此启停','This process is managed externally') : t('需本机服务明确支持','Requires native service support')} onClick={() => void act({kind})}>{label}</Button>
 const ruleView = (rules:ProxyRule[]) => rules.length ? <ol>{rules.map(r=><li key={r.ruleId}><Tag>{r.source}</Tag>{r.matcher.type}: {r.matcher.value || '*'} → {r.action.type} {r.action.targetId} {!r.enabled && t('（已禁用）',' (disabled)')}</li>)}</ol> : <Empty />
 return <>
 {feedback && <Alert showIcon type="info" title={feedback}/>}
 {d.deliveryMode === 'direct_subscription' && <Alert type="warning" showIcon title={t('直接连接：本机会接收必要上游信息。发布方式不会自动切换。','Direct connection: this device receives necessary upstream information. Delivery mode never changes automatically.')}/>}
 <Descriptions column={2} items={[{key:'service',label:t('服务','Service'),children:d.state},{key:'process',label:t('进程','Process'),children:`${d.process.state} (${d.process.ownership === 'external' ? t('外部管理','External') : t('Soha 管理','Soha managed')})`},{key:'config',label:t('配置版本','Configuration'),children:d.revision},{key:'mode',label:t('发布方式','Delivery'),children:d.deliveryMode === 'mapped_nodes' ? t('内网逐节点映射','Mapped internal nodes') : d.deliveryMode === 'gateway' ? t('聚合网关','Gateway') : d.deliveryMode === 'direct_subscription' ? t('直接连接','Direct subscription') : t('未知','Unknown')}]} />
 <Space wrap>{control('start',t('启动','Start'))}{control('stop',t('停止','Stop'))}{control('restart',t('重启','Restart'))}{control('repair',t('恢复','Repair'))}{control('refresh_subscription',t('主动更新订阅','Update subscription'),'subscription_refresh')}</Space>
 {d.process.ownership !== 'soha_owned' && <p>{t('外部进程的生命周期不可由此接管。','External process lifecycle cannot be taken over here.')} </p>}
 <Tabs items={[
 {key:'nodes',label:t('节点与策略','Nodes & policies'),children:<><p>{t('选择项来自本机实际读回；测速只在点击后发起。','Selections reflect native readback. Probes run only on request.')}</p>{(d.groups || []).map(g=><p key={g.groupId}>{g.label} <Select aria-label={g.label} style={{minWidth:200}} disabled={busy || !enabled('select') || g.type !== 'select'} value={g.selectedNodeId} options={g.nodeIds.map(id=>({value:id,label:d.nodes.find(n=>n.nodeId===id)?.label || id}))} onChange={nodeId=>void act({kind:'select',groupId:g.groupId,nodeId})}/></p>)}<Input aria-label="Approved probe profile" value={probeProfile} onChange={e=>setProbeProfile(e.target.value)} placeholder={t('管理员批准的测速方案编号','Administrator-approved probe profile')}/>{(d.nodes || []).map(n=><p key={n.nodeId}>{n.label} <Button disabled={busy || !enabled('probe') || !probeProfile.trim()} onClick={()=>void act({kind:'probe',nodeId:n.nodeId,probeProfileId:probeProfile.trim()})}>{t('测速','Probe')}</Button>{d.probe?.nodeId===n.nodeId && ` ${d.probe.latencyMilliseconds} ms`}</p>)}</>},
 {key:'rules',label:t('我的规则','My rules'),children:<PersonalRules data={d} disabled={busy || !enabled('rules')} save={async input=>{const result = await proxyRules(input);await refresh();return result}} t={t}/>},
 {key:'effective',label:t('组织与生效规则','Organization & effective rules'),children:<><p>{t('平台保护 / 组织强制 → 我的规则 → 组织默认 → 兜底。组织规则只读。','Protection / required organization → personal → organization default → fallback. Organization rules are read-only.')}</p>{ruleView(d.rules.effectiveRules || [])}{(d.rules.conflicts || []).map(c=><Alert key={c.ruleId} type="warning" title={`${c.ruleId}: ${c.reasonCode} (${c.blockingRuleId})`}/>)}<h4>{t('被屏蔽规则','Masked rules')}</h4>{ruleView(d.maskedRules || [])}</>},
 {key:'traffic',label:t('流量与连接','Traffic & connections'),children:<><p>{d.traffic.state} · {d.traffic.observedAt}</p><p>↑ {d.traffic.uploadBytesPerSecond ?? '—'} B/s · ↓ {d.traffic.downloadBytesPerSecond ?? '—'} B/s</p><p>{t('本次进程累计','Current process totals')}: ↑ {d.traffic.state === 'unavailable' ? '—' : d.traffic.uploadTotal} B · ↓ {d.traffic.state === 'unavailable' ? '—' : d.traffic.downloadTotal} B</p><p>{t('未知速率显示 —；缺口时段不推算。','Unknown rates show —; gaps are not extrapolated.')}</p><p>{d.connections.returnedCount} / {d.connections.totalActive} {d.connections.truncated && t('（已截断）',' (truncated)')}</p>{(d.connections.items || []).map(c=><p key={c.connectionId}>{c.destination || c.network || t('连接','Connection')} · ↑ {c.upload} B ↓ {c.download} B <Popconfirm title={t('关闭此连接？将影响当前传输。','Close this connection and interrupt its transfer?')} onConfirm={()=>act({kind:'close',connectionId:c.connectionId,processEpoch:d.connections.processEpoch})}><Button disabled={busy || !enabled('close_connection')}>{t('关闭此连接','Close connection')}</Button></Popconfirm></p>)}</>},
 {key:'diagnostics',label:t('DNS、日志与诊断','DNS, logs & diagnostics'),children:<>{(d.diagnostics || []).map(x=><p key={x.code}>{x.state}: {x.message}</p>)}{(d.dns || []).map(x=><p key={x.name}>{x.name}: {x.addresses.join(', ')} · {x.expiresAt}</p>)}<pre style={{whiteSpace:'pre-wrap'}}>{(d.logs || []).map(x=>`${x.occurredAt} ${x.level} ${x.message}`).join('\n')}</pre><details><summary>{t('高级诊断 / 可用功能','Advanced / capabilities')}</summary><p>PID: {d.process.pid ?? '—'}</p>{(d.capabilities || []).map(c=><p key={c.name}>{c.name}: {c.state} {c.reasonCode}</p>)}</details></>}
 ]}/></>
}
