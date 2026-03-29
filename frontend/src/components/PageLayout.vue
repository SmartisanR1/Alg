<template>
  <div class="h-full flex flex-col overflow-hidden">
    <!-- Page header -->
    <div class="px-6 py-4 border-b shrink-0 flex items-center justify-between"
         :class="isDark ? 'border-dark-border' : 'border-light-border'">
      <div class="flex items-center gap-3">
        <div class="w-8 h-8 rounded-lg flex items-center justify-center"
             :class="iconBg">
          <slot name="icon" />
        </div>
        <div>
          <h1 class="text-base font-semibold">{{ title }}</h1>
          <p class="text-xs" :class="isDark ? 'text-dark-muted' : 'text-light-muted'">{{ subtitle }}</p>
        </div>
      </div>
      <div class="flex items-center gap-2">
        <slot name="actions" />
      </div>
    </div>

    <!-- Tabs if provided -->
    <div v-if="tabs && tabs.length > 0"
         class="px-6 py-2 border-b flex items-center gap-1 shrink-0"
         :class="isDark ? 'border-dark-border' : 'border-light-border'">
      <button v-for="tab in tabs" :key="tab.id"
              class="ck-tab"
              :class="{ active: activeTab === tab.id }"
              @click="$emit('tab-change', tab.id)">
        {{ tab.label }}
      </button>
    </div>

    <!-- Content -->
    <div class="flex-1 overflow-y-auto px-6 py-5">
      <slot />
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
