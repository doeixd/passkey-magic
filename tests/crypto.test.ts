import { describe, it, expect } from 'vitest'
import { generateId, generateToken, base64url, hashToken, timingSafeEqual, isValidEmail } from '../src/crypto.js'

describe('crypto', () => {
  describe('generateId', () => {
    it('returns a UUID v4', () => {
      const id = generateId()
      expect(id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/)
    })

    it('returns unique values', () => {
      const ids = new Set(Array.from({ length: 100 }, () => generateId()))
      expect(ids.size).toBe(100)
    })
  })

  describe('generateToken', () => {
    it('returns a base64url string', () => {
      const token = generateToken()
      expect(token).toMatch(/^[A-Za-z0-9_-]+$/)
    })

    it('generates tokens of expected length', () => {
      // 32 bytes = 43 base64url chars (no padding)
      expect(generateToken(32).length).toBe(43)
      expect(generateToken(16).length).toBe(22)
    })

    it('returns unique values', () => {
      const tokens = new Set(Array.from({ length: 100 }, () => generateToken()))
      expect(tokens.size).toBe(100)
    })
  })

  describe('base64url', () => {
    it('encodes bytes to base64url', () => {
      const result = base64url(new Uint8Array([72, 101, 108, 108, 111]))
      expect(result).toBe('SGVsbG8')
    })

    it('has no padding characters', () => {
      const result = base64url(new Uint8Array([1, 2, 3]))
      expect(result).not.toContain('=')
    })

    it('uses URL-safe characters', () => {
      const result = base64url(new Uint8Array(256).fill(255))
      expect(result).not.toContain('+')
      expect(result).not.toContain('/')
    })
  })

  describe('hashToken', () => {
    it('returns consistent hashes', async () => {
      const h1 = await hashToken('test')
      const h2 = await hashToken('test')
      expect(h1).toBe(h2)
    })

    it('returns different hashes for different inputs', async () => {
      const h1 = await hashToken('a')
      const h2 = await hashToken('b')
      expect(h1).not.toBe(h2)
    })
  })

  describe('timingSafeEqual', () => {
    it('returns true for equal strings', async () => {
      expect(await timingSafeEqual('abc', 'abc')).toBe(true)
    })

    it('returns false for different strings', async () => {
      expect(await timingSafeEqual('abc', 'def')).toBe(false)
    })

    it('returns false for different lengths', async () => {
      expect(await timingSafeEqual('short', 'longer-string')).toBe(false)
    })

    it('returns true for empty strings', async () => {
      expect(await timingSafeEqual('', '')).toBe(true)
    })
  })

  describe('isValidEmail', () => {
    it('accepts valid emails', () => {
      expect(isValidEmail('user@example.com')).toBe(true)
      expect(isValidEmail('a@b.co')).toBe(true)
      expect(isValidEmail('user+tag@example.org')).toBe(true)
    })

    it('rejects invalid emails', () => {
      expect(isValidEmail('')).toBe(false)
      expect(isValidEmail('not-an-email')).toBe(false)
      expect(isValidEmail('@example.com')).toBe(false)
      expect(isValidEmail('user@')).toBe(false)
      expect(isValidEmail('user @example.com')).toBe(false)
    })

    it('rejects overly long emails', () => {
      const long = 'a'.repeat(250) + '@b.com'
      expect(isValidEmail(long)).toBe(false)
    })
  })
})
