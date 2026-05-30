<!-- frontend/src/components/AlgorithmPrinciple.vue -->
<template>
  <div class="algorithm-principle">
    <div class="principle-header">
      <h3 class="principle-title">{{ title }}</h3>
      <span :class="['algorithm-type-tag', typeClass]">
        {{ typeLabel }}
      </span>
    </div>
    <div class="principle-content">
      <div
        v-for="(section, idx) in sections"
        :key="idx"
        :class="['algorithm-principle-card', typeClass]"
      >
        <h4 class="section-title">{{ section.title }}</h4>
        <div class="section-content">
          <p v-for="(line, lIdx) in section.content" :key="lIdx" class="content-line">
            {{ line }}
          </p>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { computed } from 'vue'

const props = defineProps({
  title: {
    type: String,
    required: true
  },
  type: {
    type: String,
    required: true,
    validator: (value) => ['symmetric', 'asymmetric', 'hash', 'mac', 'gm', 'pqc', 'tools'].includes(value)
  },
  sections: {
    type: Array,
    required: true
  }
})

const typeClass = computed(() => `principle-${props.type}`)

const typeLabels = {
  symmetric: '对称加密',
  asymmetric: '非对称加密',
  hash: '哈希算法',
  mac: 'MAC/KDF',
  gm: '国密算法',
  pqc: '后量子密码',
  tools: '工具类'
}

const typeLabel = computed(() => typeLabels[props.type])
</script>

<style scoped>
.algorithm-principle {
  display: flex;
  flex-direction: column;
  gap: 1rem;
}

.principle-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.principle-title {
  font-size: 17px;
  font-weight: 600;
  color: var(--text);
  margin: 0;
}

.principle-content {
  display: flex;
  flex-direction: column;
  gap: 1rem;
}

.section-title {
  font-size: 15px;
  font-weight: 600;
  color: var(--text);
  margin: 0 0 0.5rem 0;
}

.section-content {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.content-line {
  font-size: 15px;
  line-height: 1.6;
  color: var(--muted);
  margin: 0;
}
</style>
