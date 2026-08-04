/**
 * 格式化工具函数
 */

/**
 * 从hex字符串计算字节数（内部工具）
 * @param hex hex字符串（可能包含空格）
 */
function hexToBytes(hex: string): number {
  if (!hex) return 0
  return hex.replace(/\s+/g, '').length / 2
}

/**
 * 格式化字节大小显示（内部工具）
 * @param bytes 字节数
 */
function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 bytes'
  if (bytes < 1024) return `${bytes} bytes`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
}

/**
 * 格式化hex字符串的字节大小显示，如 "32 bytes"
 * @param hex hex字符串
 */
export function formatHexBytes(hex: string): string {
  return formatBytes(hexToBytes(hex))
}
