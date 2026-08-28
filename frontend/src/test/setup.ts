import { vi } from 'vitest'

vi.stubGlobal('IS_REACT_ACT_ENVIRONMENT', true)

const getComputedStyle = window.getComputedStyle.bind(window)
vi.spyOn(window, 'getComputedStyle').mockImplementation((element) => getComputedStyle(element))

if (!window.matchMedia) {
  Object.defineProperty(window, 'matchMedia', {
    configurable: true,
    value: vi.fn().mockImplementation((query: string) => ({
      matches: false,
      media: query,
      onchange: null,
      addEventListener: vi.fn(),
      removeEventListener: vi.fn(),
      addListener: vi.fn(),
      removeListener: vi.fn(),
      dispatchEvent: vi.fn(),
    })),
  })
}
