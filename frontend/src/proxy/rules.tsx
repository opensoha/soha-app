import { useState } from 'react'
import { Alert, Button, Input, Select, Space, Switch } from 'antd'
import type { ProxyRule, ProxyRulesInput, ProxyWorkbench } from '@/types'
export function PersonalRules({data,disabled,save,t}:{data:ProxyWorkbench;disabled:boolean;save:(input:ProxyRulesInput)=>Promise<ProxyWorkbench>;t:(a:string,b:string)=>string}) {
 const [draft,setDraft] = useState<ProxyRule[]>(() => structuredClone(data.rules.rules || []))
 const [base,setBase] = useState({expectedOrgRevision:data.rules.orgRevision,expectedPersonalRevision:data.rules.personalRevision})
 const [pending,setPending] = useState(false)
 const [message,setMessage] = useState('')
 const stale = base.expectedOrgRevision!==data.rules.orgRevision || base.expectedPersonalRevision!==data.rules.personalRevision
 const update = (index:number,rule:ProxyRule) => setDraft(d=>d.map((r,i)=>i===index?rule:r))
 const move = (index:number,delta:number) => setDraft(d=>{const next=[...d];[next[index],next[index+delta]]=[next[index+delta],next[index]];return next})
 async function submit() {
  setPending(true);setMessage('')
  try {const result = await save({...base,rules:draft.map((r,order)=>({...r,order}))});setBase({expectedOrgRevision:result.rules.orgRevision,expectedPersonalRevision:result.rules.personalRevision});setMessage(t('已保存，请核对实际生效规则。','Saved. Review effective rules.'))}
  catch {setMessage(t('保存失败或版本冲突；草稿仍保留。','Save failed or revisions conflicted. Your draft is retained.'))}
  finally {setPending(false)}
 }
 return <><p>{t('组织版本','Organization revision')} {data.rules.orgRevision} · {t('个人版本','Personal revision')} {data.rules.personalRevision}</p>
 {stale && <Alert type="warning" title={t('版本已更新，草稿保留。','Revisions changed. Draft retained.')} action={<Button onClick={()=>setBase({expectedOrgRevision:data.rules.orgRevision,expectedPersonalRevision:data.rules.personalRevision})}>{t('确认新版本，保留草稿','Acknowledge revisions, keep draft')}</Button>}/>}
 {message && <Alert title={message} type="info"/>}
 {draft.map((r,i)=><section key={r.ruleId} style={{padding:'12px 0'}}><Space wrap>
 <Switch disabled={disabled || pending} aria-label={t('启用规则','Enable rule')} checked={r.enabled} onChange={enabled=>update(i,{...r,enabled})}/>
 <Select disabled={disabled || pending} aria-label="Matcher type" value={r.matcher.type} style={{minWidth:150}} options={['domain','domain_suffix','cidr','process_name','process_path','all'].map(value=>({value,label:value}))} onChange={type=>update(i,{...r,matcher:{type,value:type==='all'?undefined:r.matcher.value}})}/>
 {r.matcher.type!=='all' && <Input disabled={disabled || pending} aria-label="Matcher value" value={r.matcher.value} onChange={e=>update(i,{...r,matcher:{...r.matcher,value:e.target.value}})}/>}
 <Select disabled={disabled || pending} aria-label="Rule action" value={r.action.type} options={['reject','direct','node','group'].map(value=>({value,label:value}))} onChange={type=>update(i,{...r,action:{type}})}/>
 {(r.action.type==='node' || r.action.type==='group') && <Select disabled={disabled || pending} aria-label="Target" style={{minWidth:150}} value={r.action.targetId} options={(r.action.type==='node'?data.nodes.map(n=>({value:n.nodeId,label:n.label})):data.groups.map(g=>({value:g.groupId,label:g.label})))} onChange={targetId=>update(i,{...r,action:{...r.action,targetId}})}/>}
 <Button disabled={i===0 || disabled || pending} onClick={()=>move(i,-1)}>{t('上移','Up')}</Button><Button disabled={i===draft.length-1 || disabled || pending} onClick={()=>move(i,1)}>{t('下移','Down')}</Button>
 <Button danger disabled={disabled || pending} onClick={()=>setDraft(d=>d.filter((_,index)=>index!==i))}>{t('删除','Delete')}</Button>
 </Space></section>)}
 <Space wrap><Button disabled={disabled || pending} onClick={()=>setDraft(d=>[...d,{ruleId:crypto.randomUUID(),source:'personal',order:d.length,enabled:true,matcher:{type:'domain',value:''},action:{type:'reject'}}])}>{t('新增个人规则','Add personal rule')}</Button><Button type="primary" loading={pending} disabled={disabled || stale || pending || draft.some(r=>r.matcher.type!=='all' && !r.matcher.value?.trim() || (r.action.type==='node' || r.action.type==='group') && !r.action.targetId)} onClick={()=>void submit()}>{t('保存并验证','Save and validate')}</Button></Space>
 <p>{t('强制保护优先；直连不能绕过组织策略。失败保留草稿。','Mandatory protection takes priority. Direct cannot bypass organization policy. Failed saves preserve drafts.')}</p></>
}
