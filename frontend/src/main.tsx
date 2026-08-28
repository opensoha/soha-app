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
          colorPrimary: dark ? '#58b8a0' : '#176b5b',
          colorInfo: dark ? '#70a7d8' : '#2f6fa3',
          colorSuccess: dark ? '#8fd4aa' : '#287a4b',
          colorSuccessBg: dark ? '#203f39' : '#eef8f1',
          colorSuccessBorder: dark ? '#315e51' : '#b9d9c9',
          colorSuccessText: dark ? '#8fd4aa' : '#287a4b',
          colorTextSecondary: dark ? '#bac5c9' : '#4d5d66',
          colorWarning: dark ? '#d7aa5d' : '#946716',
          borderRadius: 6,
          fontFamily:
            '-apple-system, BlinkMacSystemFont, "Segoe UI", "PingFang SC", "Noto Sans CJK SC", sans-serif',
        },
        components: {
          Button: { controlHeight: 36 },
          Descriptions: { labelColor: dark ? '#bac5c9' : '#4d5d66' },
          Input: { controlHeight: 38 },
          Modal: { borderRadiusLG: 8 },
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
