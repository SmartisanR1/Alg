import { ref, onMounted, onUnmounted } from 'vue'
import * as runtime from '../../wailsjs/runtime/runtime'

interface WindowState {
  width: number
  height: number
  x: number
  y: number
  isMaximized: boolean
  isFullscreen: boolean
}

const STORAGE_KEY = 'windowState'

export function useWindowManager() {
  const windowState = ref<WindowState | null>(null)
  
  const saveWindowState = () => {
    const state: WindowState = {
      width: window.innerWidth,
      height: window.innerHeight,
      x: window.screenX,
      y: window.screenY,
      isMaximized: false, // 需要Wails API支持
      isFullscreen: document.fullscreenElement !== null
    }
    localStorage.setItem(STORAGE_KEY, JSON.stringify(state))
  }
  
  const loadWindowState = (): WindowState | null => {
    const saved = localStorage.getItem(STORAGE_KEY)
    if (!saved) return null
    
    try {
      const state = JSON.parse(saved) as WindowState
      // 验证窗口位置是否有效
      if (isValidWindowPosition(state)) {
        return state
      }
    } catch (e) {
      console.error('Failed to parse window state:', e)
    }
    return null
  }
  
  const isValidWindowPosition = (state: WindowState): boolean => {
    // 检查窗口是否在屏幕范围内
    const screen = window.screen
    const maxX = screen.width - 100
    const maxY = screen.height - 100
    
    return (
      state.x >= 0 &&
      state.y >= 0 &&
      state.x < maxX &&
      state.y < maxY &&
      state.width >= 800 &&
      state.height >= 600
    )
  }
  
  const applyWindowState = (state: WindowState) => {
    // 使用Wails运行时API设置窗口位置和大小
    runtime.WindowSetSize(state.width, state.height)
    runtime.WindowSetPosition(state.x, state.y)
  }
  
  onMounted(() => {
    // 加载并应用窗口状态
    const savedState = loadWindowState()
    if (savedState) {
      windowState.value = savedState
      applyWindowState(savedState)
    }
    
    // 监听窗口关闭事件
    window.addEventListener('beforeunload', saveWindowState)
  })
  
  onUnmounted(() => {
    window.removeEventListener('beforeunload', saveWindowState)
  })
  
  return {
    windowState,
    saveWindowState,
    loadWindowState
  }
}