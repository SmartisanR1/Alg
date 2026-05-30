<!-- frontend/src/components/Navigation.vue -->
<template>
  <div class="navigation">
    <div class="nav-scroll">
      <div class="nav-items">
        <template v-for="(group, gIdx) in groups" :key="group.label">
          <div v-if="gIdx > 0" class="nav-divider" />
          <button
            v-for="item in group.items"
            :key="item.path"
            :class="['nav-tab', { active: isActive(item.path) }]"
            :aria-current="isActive(item.path) ? 'page' : undefined"
            @click="navigateTo(item.path)"
          >
            <component :is="item.icon" class="nav-icon" />
            <span>{{ item.label }}</span>
          </button>
        </template>
      </div>
    </div>
  </div>
</template>

<script setup>
import { useRouter, useRoute } from 'vue-router'

const props = defineProps({
  groups: {
    type: Array,
    required: true,
    validator: (value) =>
      value.every(
        (group) =>
          typeof group.label === 'string' &&
          Array.isArray(group.items) &&
          group.items.every(
            (item) =>
              typeof item.path === 'string' &&
              typeof item.label === 'string' &&
              item.icon !== undefined
          )
      )
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
.navigation {
  overflow-x: auto;
  scrollbar-width: none;
}

.navigation::-webkit-scrollbar {
  display: none;
}

.nav-scroll {
  padding: 4px;
}

.nav-items {
  display: flex;
  gap: 2px;
}

.nav-divider {
  width: 1px;
  height: 14px;
  margin: 0 4px;
  opacity: 0.2;
  background: var(--text);
  align-self: center;
}

.nav-icon {
  width: 14px;
  height: 14px;
}
</style>
