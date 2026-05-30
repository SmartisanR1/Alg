interface CacheConfig {
  storageKey: string
  maxSize: number // 字节
  maxAge: number // 毫秒
  maxItems: number
  cleanupInterval: number // 毫秒
}

interface CacheItem<T> {
  data: T
  timestamp: number
  size: number
}

const DEFAULT_CONFIG: CacheConfig = {
  storageKey: 'cache',
  maxSize: 50 * 1024 * 1024, // 50MB
  maxAge: 30 * 24 * 60 * 60 * 1000, // 30天
  maxItems: 1000,
  cleanupInterval: 24 * 60 * 60 * 1000 // 24小时
}

export class CacheManager<T> {
  private config: CacheConfig
  private cache: Map<string, CacheItem<T>>
  private cleanupTimer: ReturnType<typeof setInterval> | null
  
  constructor(config: Partial<CacheConfig> = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config }
    this.cache = new Map()
    this.cleanupTimer = null
    
    this.loadFromStorage()
    this.startCleanupTimer()
  }
  
  set(key: string, data: T): void {
    const size = this.estimateSize(data)
    const item: CacheItem<T> = {
      data,
      timestamp: Date.now(),
      size
    }
    
    // 如果缓存已满，先清理
    if (this.cache.size >= this.config.maxItems) {
      this.cleanupOldEntries()
    }
    
    // 如果添加后超过大小限制，清理
    if (this.getTotalSize() + size > this.config.maxSize) {
      this.cleanupBySize(size)
    }
    
    this.cache.set(key, item)
    this.saveToStorage()
  }
  
  get(key: string): T | null {
    const item = this.cache.get(key)
    if (!item) return null
    
    // 检查是否过期
    if (Date.now() - item.timestamp > this.config.maxAge) {
      this.cache.delete(key)
      this.saveToStorage()
      return null
    }
    
    return item.data
  }
  
  delete(key: string): boolean {
    const deleted = this.cache.delete(key)
    if (deleted) {
      this.saveToStorage()
    }
    return deleted
  }
  
  clear(): void {
    this.cache.clear()
    this.saveToStorage()
  }
  
  private cleanupOldEntries(): void {
    const now = Date.now()
    const entries = Array.from(this.cache.entries())
    
    // 按时间排序，删除最旧的
    entries.sort((a, b) => a[1].timestamp - b[1].timestamp)
    
    for (const [key, item] of entries) {
      if (now - item.timestamp > this.config.maxAge) {
        this.cache.delete(key)
      }
    }
    
    // 如果还是超过数量限制，删除最旧的
    while (this.cache.size > this.config.maxItems * 0.8) {
      const oldestKey = this.getOldestKey()
      if (oldestKey) {
        this.cache.delete(oldestKey)
      } else {
        break
      }
    }
    
    this.saveToStorage()
  }
  
  private cleanupBySize(requiredSize: number): void {
    const entries = Array.from(this.cache.entries())
    entries.sort((a, b) => a[1].timestamp - b[1].timestamp)
    
    let freedSize = 0
    for (const [key, item] of entries) {
      if (freedSize >= requiredSize) break
      freedSize += item.size
      this.cache.delete(key)
    }
    
    this.saveToStorage()
  }
  
  private getOldestKey(): string | null {
    let oldestKey: string | null = null
    let oldestTime = Infinity
    
    for (const [key, item] of this.cache) {
      if (item.timestamp < oldestTime) {
        oldestTime = item.timestamp
        oldestKey = key
      }
    }
    
    return oldestKey
  }
  
  private getTotalSize(): number {
    let total = 0
    for (const item of this.cache.values()) {
      total += item.size
    }
    return total
  }
  
  private estimateSize(data: T): number {
    // 简单估算对象大小
    const str = JSON.stringify(data)
    return new Blob([str]).size
  }
  
  private loadFromStorage(): void {
    try {
      const saved = localStorage.getItem(this.config.storageKey)
      if (saved) {
        const entries = JSON.parse(saved)
        this.cache = new Map(entries)
      }
    } catch (e) {
      console.error('Failed to load cache from storage:', e)
    }
  }
  
  private saveToStorage(): void {
    try {
      const entries = Array.from(this.cache.entries())
      localStorage.setItem(this.config.storageKey, JSON.stringify(entries))
    } catch (e) {
      console.error('Failed to save cache to storage:', e)
    }
  }
  
  private startCleanupTimer(): void {
    this.cleanupTimer = setInterval(() => {
      this.cleanupOldEntries()
    }, this.config.cleanupInterval)
  }
  
  destroy(): void {
    if (this.cleanupTimer) {
      clearInterval(this.cleanupTimer)
    }
  }
}

// 创建默认缓存管理器实例
export const historyCache = new CacheManager({
  storageKey: 'historyCache',
  maxItems: 100,
  maxAge: 30 * 24 * 60 * 60 * 1000 // 30天
})

export const tempCache = new CacheManager({
  storageKey: 'tempCache',
  maxItems: 1000,
  maxAge: 24 * 60 * 60 * 1000 // 1天
})