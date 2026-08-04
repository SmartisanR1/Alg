import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import tailwindcss from '@tailwindcss/vite'
import { resolve } from 'path'

export default defineConfig({
  plugins: [vue(), tailwindcss()],
  resolve: {
    alias: {
      '@': resolve(__dirname, 'src'),
    },
  },
  build: {
    rollupOptions: {
      output: {
        // vite 8 (rolldown) 要求 manualChunks 为函数形式
        manualChunks(id) {
          if (/[\\/]node_modules[\\/](@vue|vue|vue-router|pinia)[\\/]/.test(id)) return 'vue-vendor'
          if (/[\\/]node_modules[\\/]@lucide[\\/]/.test(id)) return 'icons'
        },
      },
    },
    chunkSizeWarningLimit: 1000,
    // 启用 CSS 代码分割
    cssCodeSplit: true,
    // 启用源码映射（生产环境禁用）
    sourcemap: false,
  },
  // 开发服务器优化
  server: {
    // 启用预热
    warmup: {
      clientFiles: ['./src/**/*.vue'],
    },
  },
})
