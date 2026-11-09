import { useRef, useState } from 'react'
import { Alert, Button, Descriptions, Popconfirm, Space, Switch, Tag } from 'antd'
import { useQuery } from '@tanstack/react-query'
import { getLocalProxyInterception, setLocalProxyInterception } from '@/native/host'

type Translate = (zh:string,en:string)=>string
export function InterceptionPanel({t,scopeKey = "local"}:{t:Translate;scopeKey?:string}) {
 const query = useQuery({queryKey:['local-proxy-interception',scopeKey],queryFn:getLocalProxyInterception,retry:false,refetchInterval:5000,refetchIntervalInBackground:false})
 const [busy,setBusy] = useState(false)
 const locked = useRef(false)
 const [feedback,setFeedback] = useState('')
 const [pending,setPending] = useState<{systemProxy:boolean;tun:boolean}|null>(null)
 const d = query.data
 const transitional = d?.state === 'preparing' || d?.state === 'stopping'
 const recovery = !!d && (d.cleanupPending || ['cleanup_pending','failed','suspended'].includes(d.state))
 const known = !!d && ['inactive','preparing','active','stopping','suspended','cleanup_pending','failed'].includes(d.state)
 const disabled = busy || transitional || !known || !d || query.isError || query.isFetching
 async function apply(systemProxy:boolean,tun:boolean) {
  if (!d || locked.current || disabled || ((systemProxy || tun) && recovery) || (systemProxy && !d.capabilities.systemProxy) || (tun && !d.capabilities.tun)) return
  locked.current = true; setBusy(true); setPending(null); setFeedback('')
  try {
   await setLocalProxyInterception({requestId:crypto.randomUUID(),expectedGeneration:d.generation,systemProxy,tun})
   setFeedback(t('请求已返回，请核对下方实际状态。','Request returned. Review the observed state below.'))
  } catch {
   setFeedback(t('请求未确认（可能超时或状态冲突）。已尝试刷新，请核对后再操作；不会自动重试。','Request unconfirmed (possibly timeout or conflict). Refresh requested; review before trying again. No automatic retry.'))
  } finally {
   await query.refetch(); locked.current = false; setBusy(false)
  }
 }
 const labels:Record<string,string> = {inactive:t('未接管','Inactive'),preparing:t('正在准备，尚未确认接管','Preparing; takeover unconfirmed'),active:t('已接管','Active'),stopping:t('正在恢复原设置','Restoring settings'),suspended:t('已暂停','Suspended'),cleanup_pending:t('等待恢复原设置','Restoration pending'),failed:t('操作失败','Failed')}
 const scope = t('系统代理影响遵循系统 HTTP(S) 代理的应用；TUN 接管本机路由及受管 DNS。启用或恢复可能中断本机连接。','System proxy affects apps following system HTTP(S) proxy settings. TUN takes over local routes and managed DNS. Enabling or restoring may interrupt local connections.')
 const systemScope = d?.impact.systemProxyScope?.trim() || t('未知','Unknown')
 const networkService = d?.impact.networkService?.trim() || t('未知','Unknown')
 const confirmedScope = `${t('系统代理作用域','System proxy scope')}: ${systemScope} · ${t('网络服务','Network service')}: ${networkService}`
 const confirmation = <><p>{scope}</p><p>{confirmedScope}</p></>
 const actual = (value:boolean) => value ? t('已接管','Active') : t('未接管','Inactive')
 const reasons:Record<string,string> = {
  trusted_native_ui_unavailable:t('请管理员核对可信 App 与已登记的用户会话。','Ask an administrator to review the trusted app and enrolled user session.'),
  native_interception_not_configured:t('本机服务尚未配置代理，请管理员配置后刷新。','Local proxy is not configured. Ask an administrator to configure it, then refresh.'),
  native_journal_unreadable:t('恢复记录无法验证，请保留现场并联系管理员。','Recovery records cannot be verified. Preserve the current state and contact an administrator.'),
  native_apply_failed:t('启用未完成，请核对实际状态，先停用恢复再重试。','Activation did not complete. Review observed state; disable and restore before retrying.'),
  native_restore_conflict:t('系统设置被外部修改或无法验证，请管理员核对后重试恢复。','System settings changed externally or cannot be verified. Ask an administrator to review them before retrying restoration.'),
  native_session_or_network_changed:t('会话或网络已切换。请先恢复，再显式重新启用。','Session or network changed. Restore first, then explicitly enable again.'),
  native_ui_scope_required:t('请先登录，并确认本机服务已绑定当前账号与服务器；需要配置时联系管理员。','Sign in and confirm the local service is bound to this account and server. Contact an administrator if configuration is needed.'),
  native_ui_scope_mismatch:t('当前账号或服务器与本机接管绑定不一致。请切回绑定身份，或联系管理员调整。','This account or server does not match the local takeover binding. Switch to the bound identity or contact an administrator.'),
  native_ui_scope_expired:t('App 身份续验已过期，接管已暂停。请重新登录，核对恢复状态后显式启用。','App identity verification expired and takeover is suspended. Sign in again, review restoration, then explicitly enable.'),
  native_ui_scope_changed:t('App 账号或服务器已切换，接管已暂停。请先恢复原设置，再按绑定身份显式启用。','The app account or server changed and takeover is suspended. Restore original settings, then explicitly enable with the bound identity.'),
 }
 const reason = d?.reasonCode || d?.capabilities.reasonCode
 return <section aria-label={t('网络接管','Network takeover')} style={{marginBlock:20}}>
 <h3>{t('网络接管','Network takeover')}</h3><p>{scope}</p>
 <Space wrap><Tag>{d ? labels[d.state] || t('状态未知','Unknown state') : t('状态未知','Unknown state')}</Tag><Button loading={query.isFetching} onClick={()=>void query.refetch()}>{t('刷新接管状态','Refresh takeover status')}</Button></Space>
 {query.isError && <Alert showIcon type="warning" title={t('读取失败，保留上次观察；刷新成功前无法更改。','Read failed. Last observation retained; refresh successfully before changing settings.')}/>}
 {feedback && <Alert role="status" showIcon type="info" title={feedback}/>}
 {reason && <Alert showIcon type="warning" title={reasons[reason] || t('本机状态需要核对。请检查服务与系统授权，刷新后重试；仍不可用时联系管理员。','Review the local service and system authorization, then refresh. Contact an administrator if unavailable.')}/>}
 {d && <>
 <Descriptions column={1} size="small" items={[
  {key:'system',label:t('系统代理目标','System proxy target'),children:<Space><Switch aria-label={t('系统代理目标','System proxy target')} checked={d.desiredSystemProxy} disabled={disabled || recovery || (!d.capabilities.systemProxy && !d.desiredSystemProxy)} onChange={value=>setPending({systemProxy:value,tun:d.desiredTUN})}/><span>{t('实际：','Observed: ')}{actual(d.systemProxy)}</span></Space>},
  {key:'tun',label:t('TUN 目标','TUN target'),children:<Space><Switch aria-label={t('TUN 目标','TUN target')} checked={d.desiredTUN} disabled={disabled || recovery || (!d.capabilities.tun && !d.desiredTUN)} onChange={value=>setPending({systemProxy:d.desiredSystemProxy,tun:value})}/><span>{t('实际：','Observed: ')}{actual(d.tun)}</span></Space>},
  {key:'scope',label:t('系统代理作用域','System proxy scope'),children:systemScope},
  {key:'network',label:t('网络服务','Network service'),children:networkService},
  {key:'impact',label:t('后端确认的影响范围','Backend-confirmed impact'),children:`IPv4: ${d.impact.ipv4 ? t('接管','Included') : t('不接管','Excluded')} · IPv6: ${d.impact.ipv6 ? t('接管','Included') : t('不接管','Excluded')} · DNS: ${d.impact.dns ? t('受管','Managed') : t('不接管','Excluded')}`},
  {key:'time',label:t('最近观察','Last observed'),children:d.observedAt || '—'},
 ]}/>
 {(!d.capabilities.systemProxy || !d.capabilities.tun) && <Alert type="warning" showIcon title={t('部分能力不可用。请检查本机服务、系统授权和活动网络后刷新；已有接管仍可请求恢复。','Some capabilities are unavailable. Check local service, system authorization and active network, then refresh. Existing takeover can still be restored.')}/>}
 {recovery && <Alert type="warning" showIcon title={t('需先恢复原设置。外部冲突时先核对系统网络设置，再重试恢复。','Restore original settings first. For external conflicts, review system network settings before retrying restoration.')}/>}
 <Space wrap>
 {(recovery || d.desiredSystemProxy || d.desiredTUN || d.systemProxy || d.tun) && <Popconfirm placement="bottomLeft" styles={{root:{maxWidth:'calc(100vw - 32px)'}}} title={t('停用接管并恢复原设置？','Disable takeover and restore original settings?')} description={confirmation} onConfirm={()=>apply(false,false)} disabled={disabled}><Button disabled={disabled}>{t('停用并恢复','Disable and restore')}</Button></Popconfirm>}
 {!recovery && (d.desiredSystemProxy !== d.systemProxy || d.desiredTUN !== d.tun) && <Popconfirm placement="bottomLeft" styles={{root:{maxWidth:'calc(100vw - 32px)'}}} title={t('重试当前目标？','Retry current target?')} description={confirmation} onConfirm={()=>apply(d.desiredSystemProxy,d.desiredTUN)} disabled={disabled}><Button disabled={disabled}>{t('重试目标','Retry target')}</Button></Popconfirm>}
 </Space>
 </>}
 <Popconfirm placement="bottomLeft" styles={{root:{maxWidth:'calc(100vw - 32px)'}}} open={!!pending} title={t('确认更改本机网络接管？','Change local network takeover?')} description={<>{confirmation}<p>{pending && `HTTP(S): ${pending.systemProxy ? t('开启','On') : t('关闭','Off')} · TUN: ${pending.tun ? t('开启','On') : t('关闭','Off')}`}</p></>} onCancel={()=>setPending(null)} onConfirm={()=>pending && apply(pending.systemProxy,pending.tun)} okText={t('确认更改','Confirm change')} cancelText={t('取消','Cancel')}><span style={{display:'block',width:'100%'}} /></Popconfirm>
 </section>
}
