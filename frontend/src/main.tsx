import { StrictMode, useEffect, useState } from 'react'
import { createRoot } from 'react-dom/client'
import { App as AntApp, ConfigProvider, theme } from 'antd'
import enUS from 'antd/locale/en_US'
import zhCN from 'antd/locale/zh_CN'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { DesktopApp } from '@/app'
import { useAppStore } from '@/store'
import './styles.css'

const queryClient = new QueryClient({
  defaultOptions: {
    queries: { retry: false, staleTime: 30_000, refetchOnWindowFocus: false },
    mutations: { retry: false },
  },
})

function Providers() {
  const themeMode = useAppStore((state) => state.themeMode)
  const locale = useAppStore((state) => state.locale)
  const systemDark = useSystemDarkMode()
  const dark = themeMode === 'dark' || (themeMode === 'system' && systemDark)

  useEffect(() => {
    document.documentElement.dataset.theme = dark ? 'dark' : 'light'
    document.documentElement.lang = locale === 'en_US' ? 'en' : 'zh-CN'
    document.documentElement.style.colorScheme = dark ? 'dark' : 'light'
  }, [dark, locale])

  return (
    <ConfigProvider
      locale={locale === 'en_US' ? enUS : zhCN}
      theme={{
        algorithm: dark ? theme.darkAlgorithm : theme.defaultAlgorithm,
        token: {
          colorPrimary: dark ? '#4096ff' : '#1677ff',
          colorPrimaryHover: dark ? '#69b1ff' : '#4096ff',
          colorPrimaryActive: dark ? '#1677ff' : '#0958d9',
          colorPrimaryBg: dark ? 'rgba(64, 150, 255, 0.16)' : '#e6f4ff',
          colorInfo: dark ? '#69b1ff' : '#0891b2',
          colorSuccess: dark ? '#4ade80' : '#22c55e',
          colorSuccessBg: dark ? 'rgba(74, 222, 128, 0.16)' : '#f0fdf4',
          colorSuccessBorder: dark ? 'rgba(74, 222, 128, 0.32)' : '#bbf7d0',
          colorSuccessText: dark ? '#86efac' : '#16a34a',
          colorWarning: dark ? '#fb923c' : '#f97316',
          colorError: dark ? '#f87171' : '#ef4444',
          colorTextBase: dark ? '#fafafa' : '#111827',
          colorTextSecondary: dark ? '#d4d4d8' : '#4b5563',
          colorTextTertiary: dark ? '#a1a1aa' : '#6b7280',
          colorBgBase: dark ? '#07111f' : '#ffffff',
          colorBgLayout: dark ? '#07111f' : '#ffffff',
          colorBgContainer: dark ? '#0d1726' : '#ffffff',
          colorBorder: dark ? '#1e334d' : '#e5e7eb',
          colorBorderSecondary: dark ? '#28415f' : '#f0f2f5',
          borderRadius: 10,
          borderRadiusXS: 2,
          borderRadiusSM: 6,
          borderRadiusLG: 14,
          fontFamily:
            '-apple-system, BlinkMacSystemFont, "Segoe UI", "PingFang SC", "Noto Sans CJK SC", sans-serif',
        },
        components: {
          Button: { borderRadius: 6, controlHeight: 36 },
          Descriptions: { labelColor: dark ? '#d4d4d8' : '#4b5563' },
          Input: { borderRadius: 6, controlHeight: 38 },
          Modal: { borderRadiusLG: 12 },
          Segmented: {
            trackBg: dark ? '#122238' : '#f0f2f5',
            itemColor: dark ? '#d4d4d8' : '#4b5563',
            itemSelectedBg: dark ? '#4096ff' : '#0958d9',
            itemSelectedColor: dark ? '#07111f' : '#ffffff',
          },
        },
      }}
    >
      <AntApp>
        <QueryClientProvider client={queryClient}>
          <DesktopApp />
        </QueryClientProvider>
      </AntApp>
    </ConfigProvider>
  )
}

function useSystemDarkMode(): boolean {
  const [dark, setDark] = useState(() => window.matchMedia('(prefers-color-scheme: dark)').matches)
  useEffect(() => {
    const media = window.matchMedia('(prefers-color-scheme: dark)')
    const update = (event: MediaQueryListEvent) => setDark(event.matches)
    media.addEventListener('change', update)
    return () => media.removeEventListener('change', update)
  }, [])
  return dark
}

const root = document.getElementById('root')
if (!root) throw new Error('Missing application root')
createRoot(root).render(
  <StrictMode>
    <Providers />
  </StrictMode>,
)
