/**
 * Cache Layer for Scanner Service
 * Provides 24h TTL caching to reduce Render calls by ~80%
 */

import { createHash } from 'node:crypto';

interface CacheEntry<T> {
  data: T;
  timestamp: number;
  etag: string;
}

interface ScanCacheKey {
  url: string;
  scanType: 'quick' | 'deep';
  userId?: string;
}

class ScanCache {
  private cache = new Map<string, CacheEntry<any>>();
  private readonly TTL_MS = 24 * 60 * 60 * 1000; // 24 hours
  private readonly MAX_ENTRIES = 10000;
  
  private generateKey(key: ScanCacheKey): string {
    const str = `${key.scanType}:${key.url}:${key.userId || 'anon'}`;
    return createHash('sha256').update(str).digest('hex').substring(0, 32);
  }
  
  private generateETag(data: any): string {
    return createHash('sha256').update(JSON.stringify(data)).digest('hex').substring(0, 16);
  }
  
  set(key: ScanCacheKey, data: any): void {
    // Evict old entries if at capacity
    if (this.cache.size >= this.MAX_ENTRIES) {
      const oldestKey = this.cache.keys().next().value;
      if (oldestKey) this.cache.delete(oldestKey);
    }
    
    const entry: CacheEntry<any> = {
      data,
      timestamp: Date.now(),
      etag: this.generateETag(data)
    };
    
    this.cache.set(this.generateKey(key), entry);
  }
  
  get(key: ScanCacheKey): { data: any; etag: string; cached: boolean; age: number } | null {
    const cacheKey = this.generateKey(key);
    const entry = this.cache.get(cacheKey);
    
    if (!entry) return null;
    
    const age = Date.now() - entry.timestamp;
    if (age > this.TTL_MS) {
      this.cache.delete(this.generateKey(key));
      return null;
    }
    
    return {
      data: entry.data,
      etag: entry.etag,
      cached: true,
      age
    };
  }
  
  has(key: ScanCacheKey): boolean {
    const result = this.get(key);
    return result !== null;
  }
  
  delete(key: ScanCacheKey): boolean {
    return this.cache.delete(this.generateKey(key));
  }
  
  clear(): void {
    this.cache.clear();
  }
  
  // Get stats for monitoring
  getStats(): { size: number; maxSize: number; hitRate: number } {
    return {
      size: this.cache.size,
      maxSize: this.MAX_ENTRIES,
      hitRate: 0 // Would need hit/miss tracking for real implementation
    };
  }
}

// Global cache instance
export const scanCache = new ScanCache();

// Cache key generators for different scan types
export function createQuickScanKey(url: string, userId?: string) {
  return { url: normalizeUrl(url), scanType: 'quick' as const, userId };
}

export function createDeepScanKey(url: string, userId?: string) {
  return { url: normalizeUrl(url), scanType: 'deep' as const, userId };
}

function normalizeUrl(url: string): string {
  try {
    const parsed = new URL(url.startsWith('http') ? url : `https://${url}`);
    // Remove query params and fragments for caching
    return `${parsed.protocol}//${parsed.host}${parsed.pathname}`;
  } catch {
    return url;
  }
}

// Middleware for conditional requests (ETag/If-None-Match)
export function conditionalRequest(
  request: Request,
  cachedEntry: { data: any; etag: string } | null
): Response | null {
  if (!cachedEntry) return null;
  
  const ifNoneMatch = request.headers.get('if-none-match');
  if (ifNoneMatch && ifNoneMatch === cachedEntry.etag) {
    return new Response(null, { status: 304, headers: { 'ETag': cachedEntry.etag } });
  }
  
  return null;
}

export function addCacheHeaders(response: Response, cached: boolean, age?: number): Response {
  const headers = new Headers(response.headers);
  
  if (cached) {
    headers.set('X-Cache', 'HIT');
    if (age !== undefined) {
      headers.set('X-Cache-Age', String(Math.round(age / 1000)));
    }
  } else {
    headers.set('X-Cache', 'MISS');
  }
  
  headers.set('Cache-Control', 'public, max-age=86400, stale-while-revalidate=3600');
  
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers
  });
}