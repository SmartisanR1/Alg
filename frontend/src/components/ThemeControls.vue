<template>
  <div class="theme-controls flex items-center gap-1.5">
    <!-- 主题色：默认只显示调色盘图标，鼠标悬停时向左侧划出配色点，节省空间 -->
    <div class="color-picker-reveal" title="选择主题色">
      <PaletteIcon class="w-4 h-4 shrink-0" />
      <div class="color-picker">
        <button
          v-for="(scheme, color) in colorSchemes"
          :key="color"
          :class="['color-option', { active: accentColor === color }]"
          :style="{ background: scheme.accent }"
          @click="setAccentColor(color)"
        />
      </div>
    </div>

    <!-- 深浅色切换：三态循环 跟随系统 → 浅色 → 深色 → 跟随系统；
         跟随系统时右下角显示强调色小圆点作为"自动"标识 -->
    <button
      class="titlebar-icon-btn theme-toggle-btn"
      :title="toggleTitle"
      @click="cycleTheme"
    >
      <SunIcon v-if="isDark" class="w-4 h-4 text-amber-400" />
      <MoonIcon v-else class="w-4 h-4 text-violet-400" />
      <span v-if="themeMode === 'system'" class="theme-auto-dot" />
    </button>
  </div>
</template>

<script setup>
import { computed } from 'vue'
import { storeToRefs } from 'pinia'
import { PaletteIcon, SunIcon, MoonIcon } from '@lucide/vue'
import { useAppStore } from '../stores/app'

const store = useAppStore()
const { isDark, accentColor, themeMode } = storeToRefs(store)
// colorSchemes 是 store 内普通对象（非 ref），storeToRefs 不包含它，直接取即可
const colorSchemes = store.colorSchemes
const { setAccentColor, cycleTheme } = store

const toggleTitle = computed(() => {
  if (themeMode.value === 'system') return '跟随系统主题（点击手动切换）'
  return isDark.value ? '深色模式（点击：浅色 → 跟随系统）' : '浅色模式（点击：深色 → 跟随系统）'
})
</script>

<style scoped>
.theme-controls {
  white-space: nowrap;
}

/* 亮暗切换按钮：相对定位以承载"自动"小圆点 */
.theme-toggle-btn {
  position: relative;
}

/* 跟随系统模式的自动标识：右下角强调色小圆点 */
.theme-auto-dot {
  position: absolute;
  right: 1px;
  bottom: 1px;
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background: var(--accent);
  box-shadow: 0 0 0 1.5px var(--bg), 0 0 4px rgba(var(--accent-rgb), 0.6);
}
</style>
