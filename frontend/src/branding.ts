import type { Branding } from '@/types'

export function applyBranding(branding: Branding) {
  document.title = branding.appTitle || 'Soha'
  if (!branding.faviconUrl || !isSafeImageURL(branding.faviconUrl)) return
  let icon = document.querySelector<HTMLLinkElement>('link[rel="icon"]')
  if (!icon) {
    icon = document.createElement('link')
    icon.rel = 'icon'
    document.head.appendChild(icon)
  }
  icon.href = branding.faviconUrl
}

function isSafeImageURL(raw: string): boolean {
  try {
    const value = new URL(raw, window.location.origin)
    return value.origin === window.location.origin || value.protocol === 'https:'
  } catch {
    return false
  }
}
