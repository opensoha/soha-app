import { useEffect, useRef } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { createVPNIntent } from '@/api'
import { connectNetwork, disconnectNetwork, getNetworkStatus } from '@/native/host'
import { useAppStore } from '@/store'

// Kept under AuthGuard so changing pages does not cancel recovery, while logout
// clears the plan. It never retains an intent token or bypasses fresh authorization.
export function VPNRecovery() {
  const plan = useAppStore(s => s.vpnRecovery)
  const setPlan = useAppStore(s => s.setVPNRecovery)
  const platform = useAppStore(s => s.host?.app.platform)
  const client = useQueryClient()
  const observed = useRef(0)
  const status = useQuery({ queryKey: ['network-status'], queryFn: getNetworkStatus, enabled: Boolean(plan && (platform === 'windows' || platform === 'darwin')), refetchInterval: plan ? 30000 : false, refetchIntervalInBackground: true, retry: false })
  const recovery = useMutation({
    mutationKey: ['vpn-connect'],
    mutationFn: async () => {
      const current = useAppStore.getState().vpnRecovery
      if (!current || !status.data) return
      const cleared = await disconnectNetwork()
      client.setQueryData(['network-status'], cleared)
      if (cleared.state !== 'disconnected') throw new Error('VPN cleanup is incomplete')
      if (useAppStore.getState().vpnRecovery !== current) return
      const intent = await createVPNIntent({ deviceId: status.data.deviceId, profileId: current.profileId, selection: current.selection === 'auto' ? 'auto' : 'manual', ...(current.selection === 'auto' ? {} : { gatewayId: current.selection }) })
      if (useAppStore.getState().vpnRecovery !== current) return
      return connectNetwork({ intentId: intent.intentId, intentToken: intent.token, requestId: crypto.randomUUID() })
    },
    onSuccess: result => { if (result) client.setQueryData(['network-status'], result) },
    onError: () => setPlan(null),
    onSettled: () => { void client.invalidateQueries({ queryKey: ['network-status'] }) },
  })
  const mutate = recovery.mutate
  useEffect(() => {
    if (!plan || recovery.isPending || !status.data || observed.current === status.dataUpdatedAt) return
    observed.current = status.dataUpdatedAt
    if (status.data.state === 'connected') { if (plan.failures) setPlan({ ...plan, failures: 0 }); return }
    if (status.data.state !== 'degraded' || !['control_unavailable', 'lease_renewal_failed', 'endpoint_apply_failed', 'vpn_tunnel_unhealthy'].includes(status.data.diagnostic || '')) return
    const next = { ...plan, failures: plan.failures + 1 }
    if (next.failures < 3 || next.attempts >= next.max || Date.now() < next.nextAt) { setPlan(next); return }
    setPlan({ ...next, failures: 0, attempts: next.attempts + 1, nextAt: Date.now() + next.cooldown * 1000 })
    mutate()
  }, [plan, status.data, status.dataUpdatedAt, recovery.isPending, setPlan, mutate])
  return null
}
