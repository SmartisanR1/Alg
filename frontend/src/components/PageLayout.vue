<template>
  <div class="min-h-full flex flex-col">
    <!-- Page header -->
    <div class="px-3 py-2.5 border-b shrink-0 flex items-center justify-between"
         :class="isDark ? 'border-dark-border' : 'border-light-border'">
      <div class="flex items-center gap-3">
        <div class="w-8 h-8 rounded-2xl flex items-center justify-center shrink-0 shadow-sm"
             :class="iconBg">
          <slot name="icon" />
        </div>
        <div>
          <h1 class="text-[16px] font-semibold tracking-tight leading-none">{{ title }}</h1>
          <p class="text-[11px] mt-1 font-medium tracking-[0.05em]" :class="isDark ? 'text-dark-muted' : 'text-light-muted'">{{ subtitle }}</p>
        </div>
      </div>
      <div class="flex items-center gap-2">
        <slot name="actions" />
      </div>
    </div>

    <!-- Tabs if provided -->
    <div v-if="tabs && tabs.length > 0"
         class="px-3 py-1.5 border-b flex items-center gap-1 shrink-0 overflow-x-auto"
         :class="isDark ? 'border-dark-border' : 'border-light-border'">
      <button v-for="tab in tabs" :key="tab.id"
              class="ck-tab"
              :class="{ active: activeTab === tab.id }"
              @click="$emit('tab-change', tab.id)">
        {{ tab.label }}
      </button>
    </div>

    <!-- Content -->
    <div class="px-3 py-2.5">
      <div class="page-content-wrap">
        <slot />
      </div>
    </div>
  </div>
</template>

<script setup>
import { storeToRefs } from 'pinia'
import { useAppStore } from '../stores/app'

const { isDark } = storeToRefs(useAppStore())

defineProps({
  title: String,
  subtitle: String,
  iconBg: { type: String, default: 'bg-violet-500/20' },
  tabs: Array,
  activeTab: String,
})
defineEmits(['tab-change'])
</script>

<style scoped>
.page-content-wrap {
  width: 100%;
}
</style>
