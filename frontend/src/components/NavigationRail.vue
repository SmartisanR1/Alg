<template>
  <div class="navigation-rail" :class="{ expanded: isExpanded }" role="navigation" aria-label="Main navigation">
    <div class="rail-header">
      <div class="logo-container">
        <div class="logo-icon">
          <ShieldCheckIcon class="w-5 h-5 text-white" />
        </div>
        <span v-if="isExpanded" class="logo-text">CryptoKit</span>
      </div>
      <button @click="toggleExpand" class="expand-button">
        <ChevronRightIcon v-if="!isExpanded" class="w-4 h-4" />
        <ChevronLeftIcon v-else class="w-4 h-4" />
      </button>
    </div>

    <div class="rail-content">
      <div v-for="group in groups" :key="group.label" class="nav-group">
        <div v-if="isExpanded" class="group-label">{{ group.label }}</div>
        <button
          v-for="item in group.items"
          :key="item.path"
          :class="['nav-item', { active: isActive(item.path) }]"
          @click="navigateTo(item.path)"
        >
          <component :is="item.icon" class="nav-icon" />
          <span v-if="isExpanded" class="nav-text">{{ item.label }}</span>
        </button>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import { ShieldCheckIcon, ChevronRightIcon, ChevronLeftIcon } from '@lucide/vue'

const props = defineProps({
  groups: {
    type: Array,
    required: true
  }
})

const router = useRouter()
const route = useRoute()
const isExpanded = ref(false)

const isActive = (path) => route.path === path

const navigateTo = (path) => {
  router.push(path)
}

const toggleExpand = () => {
  isExpanded.value = !isExpanded.value
}
</script>

<style scoped>
.navigation-rail {
  width: 72px;
  height: 100%;
  background: var(--surface);
  border-right: 1px solid var(--border);
  display: flex;
  flex-direction: column;
  transition: width 0.3s ease;
  overflow: hidden;
}

.navigation-rail.expanded {
  width: 200px;
}

.rail-header {
  padding: 12px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  border-bottom: 1px solid var(--border);
}

.logo-container {
  display: flex;
  align-items: center;
  gap: 8px;
}

.logo-icon {
  width: 32px;
  height: 32px;
  background: linear-gradient(135deg, var(--accent), var(--accentHover));
  border-radius: 8px;
  display: flex;
  align-items: center;
  justify-content: center;
}

.logo-text {
  font-size: 14px;
  font-weight: 600;
  color: var(--text);
  white-space: nowrap;
}

.expand-button {
  width: 24px;
  height: 24px;
  background: transparent;
  border: none;
  color: var(--muted);
  cursor: pointer;
  border-radius: 4px;
  display: flex;
  align-items: center;
  justify-content: center;
}

.expand-button:hover {
  background: var(--hover);
}

.rail-content {
  flex: 1;
  overflow-y: auto;
  padding: 8px;
}

.nav-group {
  margin-bottom: 16px;
}

.group-label {
  font-size: 10px;
  font-weight: 600;
  color: var(--muted);
  text-transform: uppercase;
  letter-spacing: 0.05em;
  padding: 4px 8px;
  margin-bottom: 4px;
}

.nav-item {
  display: flex;
  align-items: center;
  gap: 8px;
  width: 100%;
  padding: 8px;
  background: transparent;
  border: none;
  color: var(--muted);
  cursor: pointer;
  border-radius: 8px;
  transition: all 0.2s ease;
  margin-bottom: 2px;
}

.nav-item:hover {
  background: var(--hover);
  color: var(--text);
}

.nav-item.active {
  background: rgba(var(--accent-rgb), 0.2);
  color: var(--accent);
}

.nav-icon {
  width: 20px;
  height: 20px;
  flex-shrink: 0;
}

.nav-text {
  font-size: 12px;
  font-weight: 500;
  white-space: nowrap;
}
</style>
