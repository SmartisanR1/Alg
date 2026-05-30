import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import { historyCache, tempCache } from '../utils/cacheManager'

export const useAppStore = defineStore('app', () => {
  const isDark = ref(true)
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

  // 切换主题
  const toggleTheme = () => {
    isDark.value = !isDark.value
    document.documentElement.classList.toggle('dark', isDark.value)
    document.documentElement.classList.toggle('light', !isDark.value)
    localStorage.setItem('theme', isDark.value ? 'dark' : 'light')
  }

  // 设置强调色
  const setAccentColor = (color: string) => {
    if (colorSchemes[color]) {
      accentColor.value = color
      applyAccentColor()
      localStorage.setItem('accent-color', color)
    }
  }

  // 应用强调色
  const applyAccentColor = () => {
    const root = document.documentElement
    const scheme = currentScheme.value

    root.style.setProperty('--accent', scheme.accent)
    root.style.setProperty('--accentHover', scheme.accentHover)
    root.style.setProperty('--accent-rgb', scheme.accentRgb)
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
    const savedTheme = localStorage.getItem('theme') || localStorage.getItem('ck-theme')
    if (savedTheme) {
      isDark.value = savedTheme === 'dark'
      document.documentElement.classList.toggle('dark', isDark.value)
      document.documentElement.classList.toggle('light', !isDark.value)
    }

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
    accentColor,
    currentScheme,
    colorSchemes,
    history,
    toast,
    historyCount,
    cacheManager,
    tempCacheManager,
    toggleTheme,
    setAccentColor,
    addToHistory,
    clearHistory,
    showToast,
    init
  }
})
