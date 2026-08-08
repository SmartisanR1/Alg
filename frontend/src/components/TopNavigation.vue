<template>
  <nav class="top-navigation" role="navigation" aria-label="Main navigation">
    <div class="nav-scroll">
      <div class="nav-items">
        <template v-for="(group, gIdx) in groups" :key="group.label">
          <div v-if="gIdx > 0" class="nav-divider" />
          <button
            v-for="item in group.items"
            :key="item.path"
            :class="['nav-item', { active: isActive(item.path) }]"
            :aria-current="isActive(item.path) ? 'page' : undefined"
            @click="navigateTo(item.path)"
          >
            <component :is="item.icon" class="nav-icon" />
            <span class="nav-label">{{ item.label }}</span>
          </button>
        </template>
      </div>
    </div>
    <div v-if="$slots.right" class="nav-right">
      <slot name="right" />
    </div>
  </nav>
</template>

<script setup>
import { useRouter, useRoute } from 'vue-router'

const props = defineProps({
  groups: {
    type: Array,
    required: true
  }
})

const router = useRouter()
const route = useRoute()

const isActive = (path) => route.path === path

const navigateTo = (path) => {
  router.push(path)
}
</script>

<style scoped>
.top-navigation {
  width: 100%;
  display: flex;
  align-items: center;
  background: var(--surface);
  border-bottom: 1px solid var(--border);
  scrollbar-width: none;
}

.top-navigation::-webkit-scrollbar {
  display: none;
}

/* 左侧导航项可横向滚动，右侧主题控件固定不动 */
.nav-scroll {
  flex: 1;
  min-width: 0;
  overflow-x: auto;
  scrollbar-width: none;
  padding: 4px 12px;
}

.nav-scroll::-webkit-scrollbar {
  display: none;
}

.nav-right {
  flex-shrink: 0;
  display: flex;
  align-items: center;
  gap: 8px;
  padding-right: 10px;
}

.nav-items {
  display: flex;
  gap: 2px;
  align-items: center;
}

.nav-divider {
  width: 1px;
  height: 15px;
  background: var(--muted);
  margin: 0 6px;
  opacity: 0.3;
}

.nav-item {
  display: flex;
  align-items: center;
  gap: 6px;
  padding: 7px 10px;
  background: transparent;
  border: 1px solid transparent;
  color: var(--muted);
  cursor: pointer;
  border-radius: 8px;
  transition: all 0.2s ease;
  white-space: nowrap;
  font-size: 13px;
  font-weight: 500;
}

.nav-icon {
  width: 16px;
  height: 16px;
  flex-shrink: 0;
}

.nav-item:hover {
  background: var(--hover);
  color: var(--text);
  border-color: var(--border);
}

.nav-item.active {
  background: rgba(var(--accent-rgb), 0.15);
  color: var(--accent);
  border-color: rgba(var(--accent-rgb), 0.3);
}

.nav-label {
  font-size: 13px;
}
</style>
