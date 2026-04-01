import { createApp } from 'vue'
import { createPinia } from 'pinia'
import router from './router'
import App from './App.vue'
import './style.css'

const app = createApp(App)
app.use(createPinia())
app.use(router)
app.mount('#app')

// Auto-trim spaces for hex-like inputs
const trimSpacesHandler = (e) => {
  const el = e.target
  if (!el || !el.classList || !el.classList.contains('ck-trim-space')) return
  const raw = el.value
  const cleaned = raw.replace(/\s+/g, '')
  if (cleaned === raw) return
  const pos = el.selectionStart
  el.value = cleaned
  if (typeof pos === 'number') {
    const diff = raw.length - cleaned.length
    const nextPos = Math.max(0, pos - diff)
    if (el.setSelectionRange) el.setSelectionRange(nextPos, nextPos)
  }
}
document.addEventListener('input', trimSpacesHandler, true)
document.addEventListener('blur', trimSpacesHandler, true)

// Prefetch core views after first paint to speed up subsequent navigation
const prefetchViews = () => {
  // 只预取最常用的几个视图，减少首屏后的加载压力
  import('./views/AsymmetricView.vue')
  import('./views/HashView.vue')
  import('./views/SymmetricView.vue')
}
if ('requestIdleCallback' in window) {
  // 等待 3 秒后或浏览器空闲时预取，不影响首屏响应
  window.requestIdleCallback(prefetchViews, { timeout: 3000 })
} else {
  setTimeout(prefetchViews, 3000)
}
