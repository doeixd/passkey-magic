const encoder = new TextEncoder()

/** Generate a random UUID v4 using Web Crypto. */
export function generateId(): string {
  return crypto.randomUUID()
}

/**
 * Generate a cryptographically random URL-safe token.
 * @param bytes - Number of random bytes (default 32 = 256 bits of entropy).
 */
export function generateToken(bytes = 32): string {
  const buf = new Uint8Array(bytes)
  crypto.getRandomValues(buf)
  return base64url(buf)
}

/** Encode a Uint8Array to a base64url string (no padding). */
export function base64url(buffer: Uint8Array): string {
  let binary = ''
  for (let i = 0; i < buffer.length; i++) {
    binary += String.fromCharCode(buffer[i])
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '')
}

/** SHA-512 hash a string and return the digest as base64url. */
export async function hashToken(token: string): Promise<string> {
  const data = encoder.encode(token)
  const hash = await crypto.subtle.digest('SHA-512', data)
  return base64url(new Uint8Array(hash))
}

/**
 * Constant-time string comparison to prevent timing attacks.
 * Returns `true` if both strings are equal. Both strings are
 * hashed first so length differences don't leak timing info.
 */
export async function timingSafeEqual(a: string, b: string): Promise<boolean> {
  const [hashA, hashB] = await Promise.all([hashToken(a), hashToken(b)])
  if (hashA.length !== hashB.length) return false
  let result = 0
  for (let i = 0; i < hashA.length; i++) {
    result |= hashA.charCodeAt(i) ^ hashB.charCodeAt(i)
  }
  return result === 0
}

/** Basic email format validation. */
export function isValidEmail(email: string): boolean {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) && email.length <= 254
}
