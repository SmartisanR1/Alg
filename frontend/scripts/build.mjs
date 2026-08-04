import { build } from 'vite'
import vue from '@vitejs/plugin-vue'
import tailwindcss from '@tailwindcss/vite'
import { resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { copyFileSync, mkdirSync } from 'node:fs'

const __dirname = fileURLToPath(new URL('..', import.meta.url))

// Wails 打包时只从 build/appicon.png 读取应用图标(macOS .icns / Windows .ico /
// Linux .png 均由其生成)。图标源文件位于项目根目录, 这里在构建阶段自动同步,
// 保证 wails build / wails dev 打包时始终使用根目录的 appicon.png。
const rootIcon = resolve(__dirname, '../appicon.png')
const buildDir = resolve(__dirname, '../build')
mkdirSync(buildDir, { recursive: true })
copyFileSync(rootIcon, resolve(buildDir, 'appicon.png'))

await build({
  configFile: false,
  root: __dirname,
  plugins: [vue(), tailwindcss()],
  resolve: {
    alias: {
      '@': resolve(__dirname, 'src'),
    },
  },
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    chunkSizeWarningLimit: 1000,
    rollupOptions: {
      output: {
        // vite 8 (rolldown) 要求 manualChunks 为函数形式
        manualChunks(id) {
          if (/[\\/]node_modules[\\/](@vue|vue|vue-router|pinia)[\\/]/.test(id)) return 'vue-vendor'
          if (/[\\/]node_modules[\\/]@lucide[\\/]/.test(id)) return 'icons'
        },
      },
    },
  },
})
