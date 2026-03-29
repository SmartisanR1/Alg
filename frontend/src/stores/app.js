import { defineStore } from 'pinia'
import { ref, watch } from 'vue'

export const useAppStore = defineStore('app', () => {
  const isDark = ref(true)
  const history = ref([])
  const toast = ref({ show: false, text: '', kind: 'info' })
  let toastTimer = null

  // Initialize theme from localStorage
  const saved = localStorage.getItem('ck-theme')
  if (saved !== null) {
    isDark.value = saved === 'dark'
  }

  function toggleTheme() {
    isDark.value = !isDark.value
    localStorage.setItem('ck-theme', isDark.value ? 'dark' : 'light')
  }

  function addHistory(entry) {
    history.value.unshift({
      ...entry,
      id: Date.now(),
      time: new Date().toLocaleTimeString(),
    })
    if (history.value.length > 50) {
      history.value = history.value.slice(0, 50)
    }
  }

  function clearHistory() {
    history.value = []
  }

  function showToast(text, kind = 'info', duration = 1400) {
    toast.value = { show: true, text, kind }
    if (toastTimer) clearTimeout(toastTimer)
    toastTimer = setTimeout(() => {
      toast.value = { ...toast.value, show: false }
    }, duration)
  }

  return { isDark, toggleTheme, history, addHistory, clearHistory, toast, showToast }
})
