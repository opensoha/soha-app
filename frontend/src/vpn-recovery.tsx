import { useEffect, useRef } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { ApiError, createVPNIntent } from '@/api'
import { connectNetwork, disconnectNetwork, getNetworkStatus } from '@/native/host'
import { useAppStore } from '@/store'
import type { VPNRecoveryPlan } from '@/store'

// Kept under AuthGuard so changing pages does not cancel recovery, while logout
// clears the plan. It never retains an intent token or bypasses fresh authorization.
export function VPNRecovery() {
  const plan = useAppStore(s => s.vpnRecovery)
  const setPlan = useAppStore(s => s.setVPNRecovery)
  const platform = useAppStore(s => s.host?.app.platform)
  const client = useQueryClient()
  const observed = useRef(0)
  const pendingRetry = useRef<VPNRecoveryPlan | null>(null)
  const status = useQuery({ queryKey: ['network-status'], queryFn: getNetworkStatus, enabled: Boolean(plan && (platform === 'windows' || platform === 'darwin')), refetchInterval: plan ? 30000 : false, refetchIntervalInBackground: true, retry: false })
  const recovery = useMutation({
    mutationKey: ['vpn-connect'],
    mutationFn: async (current: VPNRecoveryPlan) => {
      if (useAppStore.getState().vpnRecovery !== current || !status.data) return
      const cleared = await disconnectNetwork()
      client.setQueryData(['network-status'], cleared)
      if (cleared.state !== 'disconnected') throw new Error('VPN cleanup is incomplete')
      if (useAppStore.getState().vpnRecovery !== current) return
      const intent = await createVPNIntent({ deviceId: status.data.deviceId, profileId: current.profileId, selection: current.selection === 'auto' ? 'auto' : 'manual', ...(current.selection === 'auto' ? {} : { gatewayId: current.selection }) })
      if (useAppStore.getState().vpnRecovery !== current) return
      return connectNetwork({ intentId: intent.intentId, intentToken: intent.token, requestId: crypto.randomUUID() })
    },
    onSuccess: (result, current) => {
      if (useAppStore.getState().vpnRecovery !== current) return
      pendingRetry.current = null
      if (result) client.setQueryData(['network-status'], result)
    },
    onError: (error, current) => {
      if (useAppStore.getState().vpnRecovery !== current) return
      const transient = error instanceof ApiError && (error.code === 'network_error' || error.status === 429 || error.status >= 500 && error.status <= 599 && error.code !== 'response_contract_mismatch')
      if (transient && current.attempts < current.max) pendingRetry.current = current
      else { pendingRetry.current = null; setPlan(null) }
    },
    onSettled: () => { void client.invalidateQueries({ queryKey: ['network-status'] }) },
  })
  const mutate = recovery.mutate
  useEffect(() => {
    if (!plan || recovery.isPending || !status.data || observed.current === status.dataUpdatedAt) return
    observed.current = status.dataUpdatedAt
    if (status.data.state === 'connected' && status.data.sessionId) { pendingRetry.current = null; if (plan.failures) setPlan({ ...plan, failures: 0 }); return }
    const retrying = pendingRetry.current === plan && !status.data.sessionId && status.data.state !== 'connecting'
    if (!retrying && (status.data.state !== 'degraded' || !['control_unavailable', 'lease_renewal_failed', 'endpoint_apply_failed', 'endpoint_readback_mismatch', 'vpn_tunnel_unhealthy'].includes(status.data.diagnostic || ''))) return
    const next = { ...plan, failures: retrying ? 3 : plan.failures + 1 }
    if (next.attempts >= next.max) { pendingRetry.current = null; setPlan(null); return }
    if (next.failures < 3 || Date.now() < next.nextAt) { if (retrying) pendingRetry.current = next; setPlan(next); return }
    const attempt = { ...next, failures: 0, attempts: next.attempts + 1, nextAt: Date.now() + next.cooldown * 1000 }
    pendingRetry.current = null
    setPlan(attempt)
    mutate(attempt)
  }, [plan, status.data, status.dataUpdatedAt, recovery.isPending, setPlan, mutate])
  return null
}
