import { useAppStore } from '../stores/app'

/**
 * 统一的复制到剪贴板并提示逻辑，消除各视图重复实现。
 * @param {string} text 待复制内容（空值直接忽略）
 * @param {string} [message='已复制'] 成功提示文案
 * @returns {Promise<boolean>} 是否复制成功
 */
export async function copyToClipboard(text, message = '已复制') {
  if (!text) return false
  try {
    await navigator.clipboard.writeText(String(text))
    useAppStore().showToast(message)
    return true
  } catch {
    useAppStore().showToast('复制失败')
    return false
  }
}
