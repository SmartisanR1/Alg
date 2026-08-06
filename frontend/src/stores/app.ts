import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import { historyCache, tempCache } from '../utils/cacheManager'
import { SetWindowTheme } from '../../wailsjs/go/main/App'

export const useAppStore = defineStore('app', () => {
  const isDark = ref(true)
  // 主题模式：'system' 跟随系统 | 'light' 浅色 | 'dark' 深色
  const themeMode = ref<'system' | 'light' | 'dark'>('system')
  const accentColor = ref('purple')

  // 预设色彩方案
  const colorSchemes: Record<string, { accent: string; accentHover: string; accentRgb: string }> = {
    purple: {
      accent: '#7c6af7',
      accentHover: '#9080ff',
      accentRgb: '124 106 247'
    },
    blue: {
      accent: '#3b82f6',
      accentHover: '#60a5fa',
      accentRgb: '59 130 246'
    },
    teal: {
      accent: '#14b8a6',
      accentHover: '#2dd4bf',
      accentRgb: '20 184 166'
    },
    green: {
      accent: '#10b981',
      accentHover: '#34d399',
      accentRgb: '16 185 129'
    },
    orange: {
      accent: '#f97316',
      accentHover: '#fb923c',
      accentRgb: '249 115 22'
    }
  }

  // 当前色彩方案
  const currentScheme = computed(() => colorSchemes[accentColor.value])

  const history = ref<Array<{
    type: string
    data: string
    time: string
  }>>([])

  const toast = ref({
    show: false,
    text: ''
  })
  let toastTimer: ReturnType<typeof setTimeout> | null = null

  const cacheManager = ref(historyCache)
  const tempCacheManager = ref(tempCache)

  const historyCount = computed(() => history.value.length)

  // 系统当前是否为深色（WebView2 / WKWebView 均会跟随系统 prefers-color-scheme）
  const systemDark = (): boolean => {
    if (typeof window !== 'undefined' && window.matchMedia) {
      return window.matchMedia('(prefers-color-scheme: dark)').matches
    }
    return true
  }

  const syncThemeClasses = () => {
    document.documentElement.classList.toggle('dark', isDark.value)
    document.documentElement.classList.toggle('light', !isDark.value)
  }

  // 同步原生标题栏主题（仅 Windows 生效；Go 侧对非 Windows 为空实现，这里再兜底 try/catch）
  const syncWindowTheme = () => {
    const mode = themeMode.value === 'system' ? 'system' : isDark.value ? 'dark' : 'light'
    try {
      SetWindowTheme(mode)
    } catch (_) {
      /* 非 Wails 环境忽略 */
    }
  }

  // 按 themeMode 应用主题
  const applyTheme = () => {
    if (themeMode.value === 'system') {
      isDark.value = systemDark()
    } else {
      isDark.value = themeMode.value === 'dark'
    }
    syncThemeClasses()
    localStorage.setItem('theme', isDark.value ? 'dark' : 'light')
    syncWindowTheme()
  }

  // 设置主题模式并持久化
  const setThemeMode = (mode: 'system' | 'light' | 'dark') => {
    themeMode.value = mode
    localStorage.setItem('theme-mode', mode)
    applyTheme()
  }

  // 主题循环切换：跟随系统 → 手动(取反) → 另一手动 → 跟随系统
  const cycleTheme = () => {
    if (themeMode.value === 'system') {
      setThemeMode(isDark.value ? 'light' : 'dark')
    } else if (themeMode.value === 'light') {
      setThemeMode('dark')
    } else {
      setThemeMode('system')
    }
  }

  // 兼容旧调用（保留；当前 UI 已改用 toggleThemeManual）
  const toggleTheme = () => {
    isDark.value = !isDark.value
    syncThemeClasses()
    localStorage.setItem('theme', isDark.value ? 'dark' : 'light')
    syncWindowTheme()
  }

  // 设置强调色
  const setAccentColor = (color: string) => {
    if (colorSchemes[color]) {
      accentColor.value = color
      applyAccentColor()
      localStorage.setItem('accent-color', color)
    }
  }

  // 颜色工具：hex → RGB / 混合 / 转回 hex
  const hexToRgb = (hex: string) => {
    const h = hex.replace('#', '')
    return {
      r: parseInt(h.slice(0, 2), 16),
      g: parseInt(h.slice(2, 4), 16),
      b: parseInt(h.slice(4, 6), 16),
    }
  }
  const mixColor = (a: { r: number; g: number; b: number }, b: { r: number; g: number; b: number }, t: number) => ({
    r: Math.round(a.r + (b.r - a.r) * t),
    g: Math.round(a.g + (b.g - a.g) * t),
    b: Math.round(a.b + (b.b - a.b) * t),
  })
  const rgbHex = (c: { r: number; g: number; b: number }) =>
    '#' + [c.r, c.g, c.b].map((v) => v.toString(16).padStart(2, '0')).join('')

  // 由强调色生成一套 violet/indigo/purple 色阶（浅→深）。
  // Tailwind v4 的 text-violet-400 / bg-violet-500\/20 等工具类都引用 var(--color-*)，
  // 运行时覆盖这些变量即可让全应用真正跟随主题色（而非只有个别组件）。
  const buildAccentShades = (accent: string): Record<string, string> => {
    const a = hexToRgb(accent)
    const white = { r: 255, g: 255, b: 255 }
    const black = { r: 0, g: 0, b: 0 }
    const lighten = (t: number) => rgbHex(mixColor(a, white, t))
    const darken = (t: number) => rgbHex(mixColor(a, black, t))
    return {
      '--color-violet-50': lighten(0.95),
      '--color-violet-100': lighten(0.9),
      '--color-violet-200': lighten(0.78),
      '--color-violet-300': lighten(0.55),
      '--color-violet-400': lighten(0.2),
      '--color-violet-500': accent,
      '--color-violet-600': darken(0.16),
      '--color-violet-700': darken(0.3),
      '--color-indigo-50': lighten(0.95),
      '--color-indigo-100': lighten(0.9),
      '--color-indigo-400': lighten(0.18),
      '--color-indigo-500': accent,
      '--color-purple-400': lighten(0.15),
      '--color-purple-500': accent,
    }
  }

  // 应用强调色（含全局色阶覆盖）
  const applyAccentColor = () => {
    const root = document.documentElement
    const scheme = currentScheme.value
    const hover = hexToRgb(scheme.accentHover)
    const hoverRgb = `${hover.r} ${hover.g} ${hover.b}`

    root.style.setProperty('--accent', scheme.accent)
    root.style.setProperty('--accentHover', scheme.accentHover)
    root.style.setProperty('--accent-rgb', scheme.accentRgb)
    // 深/浅主题的主按钮等强调色 RGB 也跟随
    root.style.setProperty('--dark-accent-rgb', scheme.accentRgb)
    root.style.setProperty('--dark-accentHover-rgb', hoverRgb)
    root.style.setProperty('--light-accent-rgb', scheme.accentRgb)
    root.style.setProperty('--light-accentHover-rgb', hoverRgb)

    // 全局 violet/indigo/purple 色阶跟随强调色
    const shades = buildAccentShades(scheme.accent)
    for (const [name, value] of Object.entries(shades)) {
      root.style.setProperty(name, value)
    }
  }

  const addToHistory = (type: string, data: string) => {
    const entry = {
      type,
      data,
      time: new Date().toLocaleTimeString()
    }

    history.value.unshift(entry)

    if (history.value.length > 100) {
      history.value.pop()
    }

    cacheManager.value.set('history', history.value)
  }

  const clearHistory = () => {
    history.value = []
    cacheManager.value.clear()
  }

  const showToast = (text: string, duration = 2000) => {
    if (toastTimer) clearTimeout(toastTimer)
    toast.value = { show: true, text }
    toastTimer = setTimeout(() => {
      toast.value = { show: false, text: '' }
      toastTimer = null
    }, duration)
  }

  const loadHistoryFromCache = () => {
    const cached = cacheManager.value.get('history')
    if (cached) {
      history.value = cached as Array<{
        type: string
        data: string
        time: string
      }>
    }
  }

  const init = () => {
    // 主题模式：优先读取 theme-mode，兼容旧版 theme 键
    const savedMode = localStorage.getItem('theme-mode')
    if (savedMode === 'system' || savedMode === 'light' || savedMode === 'dark') {
      themeMode.value = savedMode
    } else {
      const old = localStorage.getItem('theme') || localStorage.getItem('ck-theme')
      themeMode.value = old === 'light' || old === 'dark' ? old : 'system'
    }
    applyTheme()

    // 加载保存的强调色
    const savedAccent = localStorage.getItem('accent-color')
    if (savedAccent && colorSchemes[savedAccent]) {
      accentColor.value = savedAccent
    }
    applyAccentColor()

    loadHistoryFromCache()
  }

  return {
    isDark,
    themeMode,
    accentColor,
    currentScheme,
    colorSchemes,
    history,
    toast,
    historyCount,
    cacheManager,
    tempCacheManager,
    toggleTheme,
    cycleTheme,
    setThemeMode,
    applyTheme,
    setAccentColor,
    addToHistory,
    clearHistory,
    showToast,
    init
  }
})
