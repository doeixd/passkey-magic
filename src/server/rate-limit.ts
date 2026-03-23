import type { Storage } from 'unstorage'
import type {
  AuthRateLimiter,
  RateLimitCheck,
  RateLimitDecision,
  RateLimitRoute,
  RateLimitRule,
} from '../types.js'

const DEFAULT_RATE_LIMIT_RULES: Record<RateLimitRoute, RateLimitRule> = {
  'passkey.register.options': { limit: 20, windowMs: 5 * 60 * 1000 },
  'passkey.authenticate.options': { limit: 30, windowMs: 5 * 60 * 1000 },
  'passkey.authenticate.verify': { limit: 30, windowMs: 5 * 60 * 1000 },
  'magicLink.send': { limit: 5, windowMs: 15 * 60 * 1000 },
  'magicLink.verify': { limit: 10, windowMs: 15 * 60 * 1000 },
  'qr.create': { limit: 20, windowMs: 5 * 60 * 1000 },
  'qr.scan': { limit: 30, windowMs: 5 * 60 * 1000 },
  'qr.complete': { limit: 15, windowMs: 5 * 60 * 1000 },
  'email.available': { limit: 10, windowMs: 60 * 1000 },
}

interface Bucket {
  count: number
  resetAt: number
}

export interface UnstorageRateLimiterOptions {
  /** Key prefix used inside unstorage. Defaults to `passkey-magic:ratelimit`. */
  base?: string
}

/**
 * Lightweight in-memory fixed-window rate limiter.
 *
 * Good for local development and single-instance deployments. For production
 * across multiple instances, provide a shared limiter via `AuthConfig.rateLimit`.
 */
export function createMemoryRateLimiter(): AuthRateLimiter {
  const buckets = new Map<string, Bucket>()

  return {
    async check({ key, limit, windowMs }: RateLimitCheck): Promise<RateLimitDecision> {
      const now = Date.now()
      const current = buckets.get(key)

      if (!current || now >= current.resetAt) {
        buckets.set(key, { count: 1, resetAt: now + windowMs })
        return { allowed: true }
      }

      if (current.count >= limit) {
        return { allowed: false, retryAfterMs: Math.max(0, current.resetAt - now) }
      }

      current.count += 1
      return { allowed: true }
    },
  }
}

/**
 * Shared fixed-window limiter backed by unstorage.
 *
 * This works across deployments that share the same unstorage backend.
 * It is still a simple read-modify-write design, so for strict atomicity under
 * very high contention you may want a custom limiter built on Redis/Lua or a
 * database primitive.
 */
export function createUnstorageRateLimiter(
  storage: Storage,
  options: UnstorageRateLimiterOptions = {},
): AuthRateLimiter {
  const base = options.base ?? 'passkey-magic:ratelimit'
  const keyOf = (key: string) => `${base}:${key}`

  return {
    async check({ key, limit, windowMs }: RateLimitCheck): Promise<RateLimitDecision> {
      const now = Date.now()
      const storageKey = keyOf(key)
      const current = await storage.getItem<Bucket>(storageKey)

      if (!current || typeof current.count !== 'number' || typeof current.resetAt !== 'number' || now >= current.resetAt) {
        await storage.setItem(storageKey, { count: 1, resetAt: now + windowMs })
        return { allowed: true }
      }

      if (current.count >= limit) {
        return { allowed: false, retryAfterMs: Math.max(0, current.resetAt - now) }
      }

      await storage.setItem(storageKey, {
        count: current.count + 1,
        resetAt: current.resetAt,
      })
      return { allowed: true }
    },
  }
}

export function getDefaultRateLimitRule(route: RateLimitRoute): RateLimitRule {
  return DEFAULT_RATE_LIMIT_RULES[route]
}

export async function makeRateLimitKey(parts: string[]): Promise<string> {
  let value = ''
  for (let i = 0; i < parts.length; i++) {
    const part = parts[i]
    if (i === 0) {
      value = part
      continue
    }
    value = `${value}:${part}`
  }
  return value
}

export async function normalizeIdentifier(value: string): Promise<string> {
  const normalized = value.trim().toLowerCase()
  if (normalized.length === 0) return 'unknown'
  return normalized.slice(0, 256)
}
