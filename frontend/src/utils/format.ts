/**
 * 格式化工具函数
 */

/**
 * 格式化字节大小显示
 * @param bytes 字节数
 * @returns 格式化后的字符串，如 "32 bytes", "1.5 KB"
 */
export function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 bytes'
  if (bytes < 1024) return `${bytes} bytes`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
}

/**
 * 从hex字符串计算字节数
 * @param hex hex字符串（可能包含空格）
 * @returns 字节数
 */
export function hexToBytes(hex: string): number {
  if (!hex) return 0
  return hex.replace(/\s+/g, '').length / 2
}

/**
 * 格式化hex字符串的字节大小显示
 * @param hex hex字符串
 * @returns 格式化后的字符串，如 "32 bytes"
 */
export function formatHexBytes(hex: string): string {
  return formatBytes(hexToBytes(hex))
}

/**
 * 格式化hex字符串显示（添加空格分隔）
 * @param hex hex字符串
 * @param groupSize 每组字符数，默认8
 * @returns 格式化后的字符串
 */
export function formatHexDisplay(hex: string, groupSize: number = 8): string {
  if (!hex) return ''
  const clean = hex.replace(/\s+/g, '')
  const groups = []
  for (let i = 0; i < clean.length; i += groupSize) {
    groups.push(clean.slice(i, i + groupSize))
  }
  return groups.join(' ')
}

/**
 * 格式化数字显示（添加千位分隔符）
 * @param num 数字
 * @returns 格式化后的字符串
 */
export function formatNumber(num: number): string {
  return num.toLocaleString()
}

/**
 * 格式化时间显示
 * @param ms 毫秒数
 * @returns 格式化后的字符串
 */
export function formatTime(ms: number): string {
  if (ms < 1000) return `${ms}ms`
  if (ms < 60 * 1000) return `${(ms / 1000).toFixed(1)}s`
  return `${(ms / (60 * 1000)).toFixed(1)}min`
}
