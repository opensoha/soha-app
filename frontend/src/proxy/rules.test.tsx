import { act } from 'react'
import { createRoot } from 'react-dom/client'
import { expect, it, vi } from 'vitest'
import { PersonalRules } from './rules'
import type { ProxyWorkbench } from '@/types'
it('retains edited personal draft on organization revision changes and disables save', async () => {
 const container = document.createElement('div'); document.body.append(container)
 const root = createRoot(container)
 const data = {rules:{orgRevision:1,personalRevision:1,rules:[{ruleId:'mine',source:'personal',enabled:true,order:0,matcher:{type:'domain',value:'example.test'},action:{type:'reject'}}]},nodes:[],groups:[]} as unknown as ProxyWorkbench
 const save = vi.fn()
 const render = (value:ProxyWorkbench) => root.render(<PersonalRules data={value} disabled={false} save={save} t={(_,en)=>en}/>)
 await act(async () => render(data))
 await act(async () => render({...data,rules:{...data.rules,orgRevision:2,rules:[]}}))
 expect((container.querySelector('input[aria-label="Matcher value"]') as HTMLInputElement).value).toBe('example.test')
 const button = [...container.querySelectorAll('button')].find(b=>b.textContent==='Save and validate')
 expect(button?.disabled).toBe(true)
 expect(container.textContent).toContain('Draft retained')
 await act(async () => root.unmount()); container.remove()
})
