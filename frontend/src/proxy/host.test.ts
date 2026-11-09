import { afterEach, expect, it, vi } from 'vitest'
import { proxyAction, proxyRules, proxyStatus, wailsRequestBodyHeader } from '@/native/host'
afterEach(() => vi.unstubAllGlobals())
it('uses native routes and carries close identity and both rule revisions', async () => {
 const fetcher = vi.fn().mockImplementation(async () => new Response('{}', {status:200}))
 vi.stubGlobal('fetch', fetcher)
 await proxyStatus()
 expect(fetcher.mock.calls[0][0]).toBe('/app/v1/network/proxy')
 const action = {kind:'close' as const,connectionId:'connection-1',processEpoch:'process-2'}
 await proxyAction(action)
 const init = fetcher.mock.calls[1][1] as RequestInit
 expect(JSON.parse(decodeURIComponent((init.headers as Record<string,string>)[wailsRequestBodyHeader]))).toEqual(action)
 fetcher.mockResolvedValue(new Response('{}', {status:200}))
 await proxyRules({expectedOrgRevision:3,expectedPersonalRevision:4,rules:[]})
 expect(fetcher.mock.calls[2][0]).toBe('/app/v1/network/proxy/rules')
 expect(fetcher.mock.calls[2][1].method).toBe('PUT')
})
