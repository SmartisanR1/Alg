<template>
  <div id="app-container" class="app-container flex flex-col transition-colors duration-300 group/window"
       :class="[
         isDark ? 'dark bg-dark-bg text-dark-text' : 'light bg-light-bg text-light-text',
         isMac    ? 'platform-mac'     : '',
         isWindows? 'platform-windows' : '',
         isLinux  ? 'platform-linux'   : '',
         isFullscreen ? 'fullscreen'   : 'windowed',
       ]">

     <!-- Title bar (for Wails frameless feel) - Only on Mac -->
     <div v-if="isMac" class="titlebar-drag flex items-center justify-between px-4 shrink-0 border-b relative z-[100]"
          :class="[
            isDark ? 'border-dark-border bg-dark-surface' : 'border-light-border bg-white',
            'h-12'
          ]">

       <!-- Mac Traffic Lights Placeholder + Logo section -->
       <div class="flex items-center h-full">
         <!-- Mac Traffic Lights Placeholder -->
         <div class="w-[80px] h-full shrink-0 pointer-events-none"></div>

         <!-- Logo section -->
         <div class="flex items-center gap-2.5 titlebar-nodrag transition-all duration-300 ml-1">
           <div class="w-7 h-7 rounded-lg bg-gradient-to-br from-indigo-500 to-violet-600 flex items-center justify-center shadow-lg shadow-indigo-500/20">
             <ShieldCheckIcon class="w-4 h-4 text-white" />
           </div>
           <div class="flex flex-col -space-y-0.5">
             <span class="text-sm font-bold tracking-tight" :class="isDark ? 'text-white' : 'text-gray-800'">CryptoKit</span>
             <span class="text-[9px] font-semibold text-indigo-500/90 tracking-wider uppercase">Secure Toolkit</span>
           </div>
         </div>
        </div>

        <!-- Theme -->
        <div class="flex items-center gap-2 titlebar-nodrag">
          <button @click="handleToggleTheme" class="titlebar-icon-btn">
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
    <div class="flex-1 overflow-hidden flex flex-col app-shell" :class="isDark ? 'bg-dark-bg' : 'bg-light-bg'">
      <section class="app-topbar-region shrink-0 px-2.5 pt-2 pb-1.5">
        <div class="top-shell max-w-[1280px] mx-auto">
        <div class="compact-toolbar flex items-center justify-between" :class="isDark ? 'compact-toolbar-dark' : 'compact-toolbar-light'">
           <!-- Windows/Linux Logo (Only when titlebar is hidden) -->
           <div v-if="!isMac" class="flex items-center gap-2 px-2 shrink-0 border-r border-dark-border/20 mr-2">
             <div class="w-6 h-6 bg-gradient-to-br from-indigo-500 to-violet-600 flex items-center justify-center shadow-md shadow-indigo-500/10 platform-windows:rounded-none" :class="isWindows ? '' : 'rounded-md'">
               <ShieldCheckIcon class="w-3.5 h-3.5 text-white" />
             </div>
             <span class="text-xs font-bold tracking-tight" :class="isDark ? 'text-white' : 'text-gray-800'">CryptoKit</span>
           </div>

          <!-- 扁平化功能菜单 -->
          <div class="toolbar-inline-scroll flex-1">
            <div class="flex items-center gap-1.5 px-1">
              <template v-for="(group, gIdx) in navGroups" :key="group.label">
                <!-- 组间分割线 -->
                <div v-if="gIdx > 0" class="w-[1px] h-4 mx-1 opacity-20" :class="isDark ? 'bg-white' : 'bg-black'"></div>
                
                <router-link
                  v-for="item in group.items"
                  :key="item.path"
                  :to="item.path"
                  v-slot="{ isActive }"
                >
                  <div class="tool-pill-new" :class="{ active: isActive }" v-tooltip="item.desc">
                    <component :is="item.icon" class="w-3.5 h-3.5 shrink-0" />
                    <span class="truncate">{{ item.label }}</span>
                  </div>
                </router-link>
              </template>
            </div>
          </div>

           <!-- Windows/Linux Controls (Theme only) -->
           <div v-if="!isMac" class="flex items-center gap-1.5 pl-2 border-l border-dark-border/20 ml-2 shrink-0">
             <button @click="handleToggleTheme" class="p-1.5 rounded-lg hover:bg-white/5 transition-colors">
               <SunIcon v-if="isDark" class="w-3.5 h-3.5 text-amber-400" />
               <MoonIcon v-else class="w-3.5 h-3.5 text-violet-400" />
             </button>
           </div>
        </div>
        </div>
      </section>

      <main class="app-main-region flex-1 overflow-y-auto relative px-2.5 pb-2.5">
        <div class="page-shell max-w-[1280px] mx-auto">
        <div class="page-stage min-h-full" :class="isDark ? 'page-stage-dark' : 'page-stage-light'">
          <router-view v-slot="{ Component }">
            <transition name="fade" mode="out-in">
              <component :is="Component" />
            </transition>
          </router-view>
        </div>
        </div>
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
import { ref, computed, onMounted, onUnmounted, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useAppStore } from './stores/app'
import { storeToRefs } from 'pinia'
import * as runtime from '../wailsjs/runtime/runtime'
import {
  ShieldCheckIcon, SearchIcon, SunIcon, MoonIcon,
  ZapIcon, CalculatorIcon, HistoryIcon,
  LockIcon, KeyIcon, HashIcon, ShieldHalfIcon,
  FlagIcon, AtomIcon, WrenchIcon, FileIcon, FingerprintIcon, SendIcon
} from 'lucide-vue-next'

const store = useAppStore()
const route = useRoute()
const router = useRouter()
const { isDark, history, toast } = storeToRefs(store)
const { toggleTheme, clearHistory } = store

const search = ref('')
const showHistory = ref(false)

// 平台检测
const isMac      = ref(false)
const isWindows  = ref(false)
const isLinux    = ref(false)

// 全屏检测
const isFullscreen = ref(false)

const themeMode = ref('auto') // 'light', 'dark', 'auto'
const selectedGroupLabel = ref('')

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

const activeGroup = computed(() => {
  return navGroups.find(group => group.items.some(item => item.path === route.path)) || navGroups[0]
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
})

// ── 导航结构 ────────────────────────────────────────────────
const navGroups = [
  {
    label: '联调',
    items: [
      { path: '/packet', label: '报文收发', icon: SendIcon, desc: 'TCP / TLS / TLCP 联调', badge: '核心' },
    ]
  },
  {
    label: '对称',
    items: [
      { path: '/symmetric', label: '对称算法', icon: LockIcon, desc: 'AES / SM4 / ZUC / 3DES', badge: '分组' },
      { path: '/finance', label: '金融算法', icon: FingerprintIcon, desc: 'PIN / MAC / 密钥分散', badge: '行业' },
    ]
  },
  {
    label: '非对称',
    items: [
      { path: '/asymmetric', label: '公钥算法', icon: KeyIcon, desc: 'RSA / SM2 / SM9 / ECC', badge: '公钥' },
      { path: '/cert', label: '证书管理', icon: ShieldCheckIcon, desc: 'X.509 / CSR / 证书链', badge: 'PKI' },
      { path: '/pqc', label: '后量子', icon: AtomIcon, desc: 'FIPS 203 / 204 / 205', badge: 'PQC' },
    ]
  },
  {
    label: '摘要',
    items: [
      { path: '/hash', label: '哈希摘要', icon: HashIcon, desc: 'SHA系列 / SM3 / BLAKE', badge: '哈希' },
      { path: '/mac', label: 'MAC / KDF', icon: ShieldHalfIcon, desc: 'HMAC / HKDF / PBKDF2', badge: '认证' },
    ]
  },
  {
    label: '工具',
    items: [
      { path: '/tools', label: '转换工具', icon: WrenchIcon, desc: 'Base64 / Hex / ASN.1', badge: '通用' },
      { path: '/bigint', label: '大数运算', icon: CalculatorIcon, desc: '大数模幂 / 进制转换', badge: '数学' },
      { path: '/file', label: '文件加密', icon: FileIcon, desc: '文件流加解密', badge: '文件' },
    ]
  }
]

watch(
  () => route.path,
  () => {
    selectedGroupLabel.value = activeGroup.value.label
  },
  { immediate: true }
)
</script>

<style>
.compact-toolbar {
  @apply rounded-2xl border px-2 py-1.5;
  backdrop-filter: blur(18px);
}

.toolbar-inline-scroll {
  @apply overflow-x-auto;
  scrollbar-width: none; /* Firefox */
}
.toolbar-inline-scroll::-webkit-scrollbar {
  display: none; /* Chrome/Safari */
}

.tool-pill-new {
  @apply flex items-center gap-1.5 px-2.5 py-1.5 rounded-xl text-[12px] font-medium transition-all cursor-pointer whitespace-nowrap;
  border: 1px solid transparent;
}

.app-container.dark .tool-pill-new {
   @apply text-dark-muted hover:text-white hover:bg-white/5 rounded-none;
 }
 .app-container.light .tool-pill-new {
   @apply text-slate-500 hover:text-slate-900 hover:bg-slate-100 rounded-none;
 }
 
 .tool-pill-new.active {
   @apply shadow-sm;
 }
 .app-container.dark .tool-pill-new.active {
   @apply bg-violet-500/20 text-violet-400 border-violet-500/30;
 }
 .app-container.light .tool-pill-new.active {
   @apply bg-white text-violet-600 border-slate-200;
 }

.top-shell,
.page-shell {
  width: 100%;
}

.titlebar-icon-btn {
  @apply w-8 h-8 rounded-xl inline-flex items-center justify-center transition-colors border;
}

.app-container.dark .titlebar-icon-btn {
  @apply border-dark-border hover:bg-dark-hover;
}

.app-container.light .titlebar-icon-btn {
  @apply border-slate-200 hover:bg-slate-100;
}

.compact-toolbar-dark {
  @apply border-dark-border;
  background: linear-gradient(180deg, rgba(24, 24, 34, 0.94), rgba(20, 20, 30, 0.9));
  box-shadow: inset 0 1px 0 rgba(255,255,255,0.03);
}

.compact-toolbar-light {
  @apply border-light-border shadow-sm shadow-slate-200/70;
  background: linear-gradient(180deg, rgba(255,255,255,0.95), rgba(248,250,252,0.92));
}

.toolbar-inline {
  @apply flex items-center gap-1.5 overflow-x-auto;
}

.toolbar-group-select {
  @apply shrink-0 relative inline-flex items-center;
}

.toolbar-select-label {
  @apply absolute left-2.5 top-1/2 -translate-y-1/2 text-[11px] font-semibold pointer-events-none opacity-70;
}

.toolbar-select {
  @apply h-9 min-w-[144px] rounded-xl border pl-11 pr-9 text-[12px] font-semibold outline-none appearance-none;
  background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 24 24' fill='none' stroke='%238888a8' stroke-width='2'%3E%3Cpolyline points='6 9 12 15 18 9'%3E%3C/polyline%3E%3C/svg%3E");
  background-repeat: no-repeat;
  background-position: right 12px center;
}

.app-container.dark .toolbar-select {
  @apply bg-dark-bg border-dark-border text-dark-text;
}

.app-container.light .toolbar-select {
  @apply bg-slate-50 border-slate-200 text-slate-800;
}

.tool-pill {
  @apply shrink-0 inline-flex items-center gap-1.5 px-2.5 py-1 h-9 rounded-xl border text-[12px] font-semibold transition-all duration-200;
}

.app-container.dark .tool-pill {
  @apply border-dark-border bg-dark-bg/70 text-dark-muted hover:text-dark-text;
}

.app-container.dark .tool-pill.active {
  @apply border-violet-500/30 bg-violet-500/10 text-violet-300 shadow-sm shadow-violet-500/10;
}

.app-container.light .tool-pill {
  @apply border-slate-200 bg-slate-50 text-slate-600 hover:text-slate-900;
}

.app-container.light .tool-pill.active {
  @apply border-violet-200 bg-violet-50 text-violet-700 shadow-sm shadow-violet-200/40;
}

.page-stage {
  @apply rounded-none border overflow-hidden;
  min-height: 100%;
}

.app-container.platform-windows .page-stage {
  border-radius: 0;
}

.page-stage-dark {
  @apply bg-dark-surface border-dark-border;
}

.page-stage-light {
  @apply bg-white/95 border-light-border shadow-md shadow-slate-200/70;
}

.app-container.dark .titlebar-drag {
  background: #161622 !important;
  border-color: #2a2a3e !important;
}

.app-container.fullscreen .app-topbar-region {
  padding-left: 14px;
  padding-right: 14px;
  padding-top: 12px;
  padding-bottom: 8px;
}

.app-container.fullscreen .app-main-region {
  padding-left: 14px;
  padding-right: 14px;
  padding-bottom: 14px;
}

.app-container.fullscreen .compact-toolbar {
  padding: 10px 12px;
}

.app-container.fullscreen .tool-pill {
  height: 36px;
  padding-left: 12px;
  padding-right: 12px;
  font-size: 13px;
}

.app-container.fullscreen .page-stage {
  border-radius: 16px;
}

.fade-enter-active, .fade-leave-active {
  transition: opacity 0.2s ease, transform 0.2s ease;
}
.fade-enter-from, .fade-leave-to {
  opacity: 0;
  transform: translateY(4px);
}

/* Windows: outermost container square corners only */
.app-container.platform-windows .compact-toolbar {
  border-radius: 0;
}
.app-container.platform-windows .page-stage {
  border-radius: 0;
}
.app-container.platform-windows {
  border-radius: 0;
}
</style>
