import { act } from 'react'
import { createRoot } from 'react-dom/client'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { afterEach, expect, it, vi } from 'vitest'
import { InterceptionPanel } from './interception'
import type { LocalProxyInterceptionStatus } from '@/types'
vi.stubGlobal('ResizeObserver',class { observe = vi.fn(); unobserve = vi.fn(); disconnect = vi.fn() })
const host = vi.hoisted(()=>({get:vi.fn(),set:vi.fn()}))
vi.mock('@/native/host',()=>({getLocalProxyInterception:host.get,setLocalProxyInterception:host.set}))
const initial:LocalProxyInterceptionStatus = {generation:4,desiredSystemProxy:false,desiredTUN:false,systemProxy:false,tun:false,state:'inactive',cleanupPending:false,observedAt:'2026-11-08T00:00:00Z',capabilities:{systemProxy:true,tun:true},impact:{ipv4:true,ipv6:false,dns:true,systemProxyScope:'Current signed-in user',networkService:'Wi-Fi'}}
let dispose:()=>Promise<void>
afterEach(async()=>{await dispose?.();host.get.mockReset();host.set.mockReset()})
async function mount(status = initial) {
 host.get.mockResolvedValue(status)
 const client = new QueryClient({defaultOptions:{queries:{gcTime:0}}})
 const container = document.createElement('div');document.body.append(container)
 const root = createRoot(container)
 await act(async()=>{root.render(<QueryClientProvider client={client}><InterceptionPanel t={(_,en)=>en}/></QueryClientProvider>);await new Promise(r=>setTimeout(r,20))})
 await act(async()=>{await new Promise(r=>setTimeout(r,20))})
 dispose = async()=>{await act(async()=>root.unmount());client.clear();container.remove()}
 return container
}
async function click(label:string) {
 const button = [...document.querySelectorAll('button')].find(b=>b.textContent===label)
 expect(button).toBeTruthy()
 await act(async()=>{button!.click();await new Promise(r=>setTimeout(r,30))})
}
it('starts inactive without writing and presents real IPv6 impact',async()=>{
 const c = await mount()
 expect(c.textContent).toContain('IPv6: Excluded')
 expect(c.textContent).toContain('Current signed-in user')
 expect(c.textContent).toContain('Wi-Fi')
 expect([...c.querySelectorAll('[role=switch]')].every(s=>s.getAttribute('aria-checked')==='false')).toBe(true)
 expect(host.set).not.toHaveBeenCalled()
})
it('keeps desired and observed state distinct while preparing',async()=>{
 const c = await mount({...initial,state:'preparing',desiredTUN:true})
 expect(c.textContent).toContain('Preparing; takeover unconfirmed')
 expect(c.textContent).toContain('Observed: Inactive')
 expect([...c.querySelectorAll<HTMLButtonElement>('[role=switch]')].every(b=>b.disabled)).toBe(true)
})
it('blocks unavailable capabilities without an implicit activation',async()=>{
 const c = await mount({...initial,capabilities:{systemProxy:false,tun:false},impact:{ipv4:false,ipv6:false,dns:false}})
 expect(c.textContent).toContain('System proxy scopeUnknown')
 expect(c.textContent).toContain('Network serviceUnknown')
 expect([...c.querySelectorAll<HTMLButtonElement>('[role=switch]')].every(b=>b.disabled)).toBe(true)
 expect(host.set).not.toHaveBeenCalled()
})
it('refreshes conflict without replaying a write',async()=>{
 const c = await mount()
 host.set.mockRejectedValue(new Error('conflict'))
 await act(async()=>c.querySelector<HTMLButtonElement>('[role=switch]')!.click())
 expect(document.querySelector('.ant-popconfirm-description')?.textContent).toContain('System proxy scope: Current signed-in user')
 expect(document.querySelector('.ant-popconfirm-description')?.textContent).toContain('Network service: Wi-Fi')
 await click('Confirm change')
 expect(host.set).toHaveBeenCalledTimes(1)
 expect(host.set.mock.calls[0][0]).toMatchObject({expectedGeneration:4,systemProxy:true,tun:false})
 expect(host.get.mock.calls.length).toBeGreaterThan(1)
 expect(c.textContent).toContain('No automatic retry')
})
it('permits restoration with unavailable capabilities and pending cleanup',async()=>{
 const c = await mount({...initial,state:'cleanup_pending',cleanupPending:true,desiredTUN:true,capabilities:{systemProxy:false,tun:false}})
 host.set.mockResolvedValue(initial)
 expect(c.textContent).toContain('Some capabilities are unavailable')
 await click('Disable and restore')
 await click('OK')
 expect(host.set.mock.calls[0][0]).toMatchObject({systemProxy:false,tun:false})
})
