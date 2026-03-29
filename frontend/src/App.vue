<template>
  <div id="app-container" class="app-container flex flex-col transition-colors duration-300 group/window"
       :class="[
         isDark ? 'dark bg-dark-bg text-dark-text' : 'light bg-light-bg text-light-text',
         isMac    ? 'platform-mac'     : '',
         isWindows? 'platform-windows' : '',
         isLinux  ? 'platform-linux'   : '',
         isFullscreen ? 'fullscreen'   : 'windowed',
       ]">

    <!-- Title bar (for Wails frameless feel) -->
    <div class="titlebar-drag flex items-center justify-between px-4 shrink-0 border-b relative z-[100]"
         :class="[
           isDark ? 'border-dark-border bg-dark-surface' : 'border-light-border bg-white',
           isMac ? 'h-12' : 'h-11'
         ]">

      <!-- Mac Traffic Lights Placeholder + Logo section -->
      <div class="flex items-center h-full">
        <!-- Mac Traffic Lights Placeholder -->
        <div v-if="isMac" class="w-[80px] h-full shrink-0 pointer-events-none"></div>

        <!-- Logo section -->
        <div class="flex items-center gap-2.5 titlebar-nodrag transition-all duration-300"
             :class="isMac ? 'ml-1' : 'ml-0'">
          <div class="w-7 h-7 rounded-lg bg-gradient-to-br from-indigo-500 to-violet-600 flex items-center justify-center shadow-lg shadow-indigo-500/20">
            <ShieldCheckIcon class="w-4 h-4 text-white" />
          </div>
          <div class="flex flex-col -space-y-0.5">
            <span class="text-sm font-bold tracking-tight" :class="isDark ? 'text-white' : 'text-gray-800'">CryptoKit</span>
            <span class="text-[9px] font-semibold text-indigo-500/90 tracking-wider uppercase">Secure Toolkit</span>
          </div>
        </div>
      </div>

      <!-- Search & Theme -->
      <div class="flex items-center gap-3 titlebar-nodrag" :class="!isMac ? 'mr-[120px]' : ''">
        <div class="relative group/search hidden md:block">
          <SearchIcon class="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-dark-muted" />
          <input v-model="search" type="text" placeholder="快速搜索算法..."
                 class="w-48 lg:w-64 h-8 pl-8 pr-10 text-xs rounded-lg border outline-none transition-all search-input"
                 :class="isDark ? 'bg-dark-bg border-dark-border' : 'bg-gray-100 border-transparent focus:bg-white focus:border-light-accent'" />

          <!-- Search Results Dropdown -->
          <div v-if="search" class="absolute left-0 top-10 w-full z-[100] rounded-xl border shadow-2xl overflow-hidden"
               :class="isDark ? 'bg-dark-card border-dark-border' : 'bg-white border-light-border shadow-gray-200'">
            <div v-if="filteredAlgos.length === 0" class="p-4 text-center text-xs text-dark-muted">未找到相关算法</div>
            <router-link v-for="algo in filteredAlgos" :key="algo.path" :to="algo.path"
                         @click="search = ''"
                         class="flex items-center gap-3 px-4 py-2.5 text-xs hover:bg-violet-500/10 transition-colors">
              <component :is="algo.icon" class="w-3.5 h-3.5 text-violet-400" />
              <span>{{ algo.label }}</span>
            </router-link>
          </div>
        </div>
        <button ref="historyBtnRef" @click="showHistory = !showHistory" class="p-2 rounded-lg hover:bg-dark-hover transition-colors relative">
          <HistoryIcon class="w-4 h-4 text-dark-muted" />
          <span v-if="history.length" class="absolute top-1 right-1 w-1.5 h-1.5 bg-violet-500 rounded-full"></span>
        </button>
        <button @click="handleToggleTheme" class="p-2 rounded-lg hover:bg-dark-hover transition-colors">
          <SunIcon v-if="isDark" class="w-4 h-4 text-amber-400" />
          <MoonIcon v-else class="w-4 h-4 text-violet-400" />
        </button>
      </div>
    </div>

    <!-- Transparent overlay: close history when clicking outside the panel -->
    <div v-if="showHistory" class="fixed inset-0 z-40" @click="showHistory = false" style="background:transparent"></div>

    <!-- History Dropdown -->
    <transition name="fade">
      <div v-if="showHistory" class="absolute right-4 top-14 w-80 max-h-[400px] overflow-y-auto z-50 rounded-xl border shadow-2xl p-3"
           :class="isDark ? 'bg-dark-card border-dark-border' : 'bg-white border-light-border shadow-gray-200'"
           @click.stop>
        <div class="flex items-center justify-between mb-3 px-1">
          <h3 class="text-xs font-semibold uppercase tracking-wider text-dark-muted">最近记录</h3>
          <button @click="clearHistory" class="text-[10px] text-red-400 hover:text-red-300">清空</button>
        </div>
        <div v-if="!history.length" class="py-8 text-center text-dark-muted text-xs">暂无历史记录</div>
        <div v-else class="space-y-2">
          <div v-for="(item, i) in history" :key="i" class="p-2 rounded-lg border transition-all group/item"
               :class="isDark ? 'bg-dark-bg/50 border-dark-border/30 hover:border-dark-accent/30' : 'bg-gray-50 border-light-border hover:border-violet-200'">
            <div class="flex justify-between items-start mb-1">
              <span class="text-[10px] font-medium text-violet-500">{{ item.type }}</span>
              <span class="text-[9px] text-dark-muted">{{ item.time }}</span>
            </div>
            <p class="text-[11px] font-mono truncate" :class="isDark ? 'text-dark-text' : 'text-light-text'">{{ item.data }}</p>
          </div>
        </div>
      </div>
    </transition>

      <!-- Main Content -->
      <div class="flex-1 flex overflow-hidden">
        <!-- Sidebar -->
        <aside class="w-60 shrink-0 border-r flex flex-col p-4 gap-6 overflow-y-auto"
               :class="isDark ? 'border-dark-border bg-dark-surface' : 'border-light-border bg-gray-50/50'">

          <div v-for="group in navGroups" :key="group.label" class="space-y-1">
            <p class="sidebar-group-label text-[10px] px-3 mb-2 font-bold opacity-50 uppercase tracking-widest">{{ group.label }}</p>
            <router-link v-for="item in group.items" :key="item.path" :to="item.path"
                         v-slot="{ isActive }">
              <div class="nav-item" :class="{ 'active': isActive, 'sidebar-item-active': isActive && isDark }">
                <component :is="item.icon" class="w-4.5 h-4.5 shrink-0" />
                <span class="flex-1 text-sm font-semibold">{{ item.label }}</span>
                <span v-if="item.badge" class="px-1.5 py-0.5 rounded-md bg-violet-500/20 text-violet-400 text-[9px] font-bold uppercase">{{ item.badge }}</span>
              </div>
            </router-link>
          </div>

        <div class="mt-auto pt-5 border-t border-dark-border/50 px-3">
          <div class="flex items-center gap-2 mb-1">
            <div class="w-2 h-2 rounded-full bg-emerald-500 shadow-[0_0_8px_rgba(16,185,129,0.5)]"></div>
            <span class="text-xs font-medium text-dark-muted">本地后端已就绪</span>
          </div>
          <p class="text-[10px] text-dark-muted/60">Go + Wails v2 + Vue 3</p>
        </div>
      </aside>

      <!-- Page Content -->
      <main class="flex-1 overflow-hidden relative" :class="isDark ? 'bg-dark-bg' : 'bg-light-bg'">
        <router-view v-slot="{ Component }">
          <transition name="fade" mode="out-in">
            <component :is="Component" />
          </transition>
        </router-view>
      </main>
    </div>

    <!-- Toast -->
    <transition name="fade">
      <div v-if="toast.show" class="ck-toast" :class="isDark ? 'ck-toast-dark' : 'ck-toast-light'">
        {{ toast.text }}
      </div>
    </transition>
  </div>
</template>

<script setup>
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { useAppStore } from './stores/app'
import { storeToRefs } from 'pinia'
import * as runtime from '../wailsjs/runtime/runtime'
import {
  ShieldIcon, ShieldCheckIcon, SearchIcon, SunIcon, MoonIcon,
  ZapIcon, CalculatorIcon, HistoryIcon, XIcon,
  LockIcon, KeyIcon, HashIcon, ShieldHalfIcon,
  FlagIcon, AtomIcon, WrenchIcon, FileIcon, FingerprintIcon
} from 'lucide-vue-next'

const store = useAppStore()
const { isDark, history, toast } = storeToRefs(store)
const { toggleTheme, clearHistory } = store

const search = ref('')
const showHistory = ref(false)
const historyBtnRef = ref(null)

// 平台检测
const isMac      = ref(false)
const isWindows  = ref(false)
const isLinux    = ref(false)

// 全屏检测
const isFullscreen = ref(false)

const themeMode = ref('auto') // 'light', 'dark', 'auto'

// ── 主题逻辑 ────────────────────────────────────────────────
const updateThemeByTime = () => {
  if (themeMode.value !== 'auto') return
  const hour = new Date().getHours()
  const shouldBeDark = hour >= 18 || hour < 7
  if (isDark.value !== shouldBeDark) toggleTheme()
}

const handleToggleTheme = () => {
  if (themeMode.value === 'auto') {
    themeMode.value = isDark.value ? 'light' : 'dark'
    toggleTheme()
  } else {
    toggleTheme()
    themeMode.value = isDark.value ? 'dark' : 'light'
  }
}

// ── 全屏状态检测 ────────────────────────────────────────────
const checkFullscreen = () => {
  // 检测 macOS 原生全屏或 Windows 最大化铺满
  isFullscreen.value = (
    window.innerWidth  === window.screen.width &&
    window.innerHeight >= window.screen.height - 10  // -10 容错 taskbar/dock
  )
}

// 历史记录面板通过透明遮罩关闭（更可靠）
// handleDocClick 已移除，改用 overlay 方案

// ── 搜索 ────────────────────────────────────────────────────
const allAlgos = computed(() => navGroups.flatMap(g => g.items))

const filteredAlgos = computed(() => {
  if (!search.value) return []
  const q = search.value.toLowerCase()
  return allAlgos.value.filter(a =>
    a.label.toLowerCase().includes(q) ||
    a.path.toLowerCase().includes(q)
  ).slice(0, 8)
})

// ── 生命周期 ────────────────────────────────────────────────
onMounted(async () => {
  // 从 Wails 运行时获取平台信息
  if (runtime.Environment) {
    try {
      const env = await runtime.Environment()
      isMac.value     = env.platform === 'darwin'
      isWindows.value = env.platform === 'windows'
      isLinux.value   = env.platform === 'linux'
    } catch (_) {}
  }

  // 全屏检测
  checkFullscreen()
  window.addEventListener('resize', checkFullscreen)

  // 主题自动切换
  updateThemeByTime()
  setInterval(updateThemeByTime, 60000)


})

onUnmounted(() => {
  window.removeEventListener('resize', checkFullscreen)
  // no document click listeners needed (overlay handles close)
})

// ── 导航结构 ────────────────────────────────────────────────
const navGroups = [
  {
    label: '🌐 国际算法',
    items: [
      { path: '/symmetric',  label: '对称算法',     icon: LockIcon },
      { path: '/asymmetric', label: '非对称算法',    icon: KeyIcon },
      { path: '/hash',       label: 'Hash / HMAC',  icon: HashIcon },
      { path: '/mac',        label: 'MAC / KDF',    icon: ShieldHalfIcon },
    ]
  },
  {
    label: '🏦 金融密码',
    items: [
      { path: '/finance', label: '金融数据密码', icon: FingerprintIcon },
    ]
  },
  {
    label: '🇨🇳 国密算法',
    items: [
      { path: '/gm', label: 'SM2 / SM3 / SM4', icon: FlagIcon },
    ]
  },
  {
    label: '⚛️ 后量子 PQC',
    items: [
      { path: '/pqc',   label: 'FIPS 203/204/205', icon: AtomIcon, badge: 'NIST' },
      { path: '/gmpqc', label: '国密 PQC (调研)',   icon: ZapIcon },
    ]
  },
  {
    label: '🛠️ 工具',
    items: [
      { path: '/tools',   label: '编解码工具箱', icon: WrenchIcon },
      { path: '/bigint',  label: '大数运算',     icon: CalculatorIcon },
      { path: '/cert',    label: '证书管理',     icon: ShieldCheckIcon },
      { path: '/file',    label: '文件加解密',   icon: FileIcon },
    ]
  }
]
</script>

<style>
.nav-item {
  @apply flex items-center gap-3 px-3 py-2 rounded-xl text-sm font-medium transition-all duration-200 cursor-pointer mb-1;
}
.dark .nav-item {
  @apply text-dark-muted hover:bg-dark-hover hover:text-dark-text;
}
.nav-item.active {
  @apply bg-violet-500/15 text-violet-400 shadow-sm shadow-violet-500/10;
}
:not(.dark) .nav-item {
  @apply text-light-muted hover:bg-light-hover hover:text-light-text;
}
:not(.dark) .nav-item.active {
  @apply bg-violet-50 text-violet-600;
}

.fade-enter-active, .fade-leave-active {
  transition: opacity 0.2s ease, transform 0.2s ease;
}
.fade-enter-from, .fade-leave-to {
  opacity: 0;
  transform: translateY(4px);
}
</style>
