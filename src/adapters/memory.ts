import { timingSafeEqual } from '../crypto.js'
import type { Credential, QRSession, Session, StorageAdapter, User } from '../types.js'

interface TTLEntry<T> {
  value: T
  expiresAt: number
}

/**
 * In-memory storage adapter for development and testing.
 * Data is not persisted across restarts.
 */
export function memoryAdapter(): StorageAdapter {
  const users = new Map<string, User>()
  const credentials = new Map<string, Credential>()
  const sessions = new Map<string, Session>()
  const challenges = new Map<string, TTLEntry<string>>()
  const magicLinks = new Map<string, TTLEntry<{ email: string }>>()
  const qrSessions = new Map<string, QRSession>()

  function isExpired<T>(entry: TTLEntry<T> | undefined): boolean {
    return !entry || Date.now() > entry.expiresAt
  }

  return {
    // ── Users ──
    async createUser(user) {
      users.set(user.id, { ...user })
      return { ...user }
    },
    async getUserById(id) {
      const user = users.get(id)
      return user ? { ...user } : null
    },
    async getUserByEmail(email) {
      for (const user of users.values()) {
        if (user.email === email) return { ...user }
      }
      return null
    },
    async updateUser(id, update) {
      const user = users.get(id)
      if (!user) throw new Error(`User not found: ${id}`)
      const updated = { ...user, ...update }
      users.set(id, updated)
      return { ...updated }
    },
    async deleteUser(id) {
      users.delete(id)
    },

    // ── Credentials ──
    async createCredential(cred) {
      credentials.set(cred.id, { ...cred })
      return { ...cred }
    },
    async getCredentialById(id) {
      const cred = credentials.get(id)
      return cred ? { ...cred } : null
    },
    async getCredentialsByUserId(userId) {
      const result: Credential[] = []
      for (const cred of credentials.values()) {
        if (cred.userId === userId) result.push({ ...cred })
      }
      return result
    },
    async updateCredential(id, update) {
      const cred = credentials.get(id)
      if (!cred) throw new Error(`Credential not found: ${id}`)
      if (update.counter !== undefined) cred.counter = update.counter
      if (update.label !== undefined) cred.label = update.label
    },
    async deleteCredential(id) {
      credentials.delete(id)
    },

    // ── Sessions ──
    async createSession(session) {
      sessions.set(session.id, { ...session })
      return { ...session }
    },
    async getSessionByToken(token) {
      for (const session of sessions.values()) {
        if (await timingSafeEqual(session.token, token)) {
          if (new Date() > session.expiresAt) {
            sessions.delete(session.id)
            return null
          }
          return { ...session }
        }
      }
      return null
    },
    async getSessionsByUserId(userId) {
      const result: Session[] = []
      for (const session of sessions.values()) {
        if (session.userId === userId) {
          if (new Date() > session.expiresAt) {
            sessions.delete(session.id)
          } else {
            result.push({ ...session })
          }
        }
      }
      return result
    },
    async deleteSession(id) {
      sessions.delete(id)
    },
    async deleteSessionsByUserId(userId) {
      for (const [id, session] of sessions) {
        if (session.userId === userId) sessions.delete(id)
      }
    },

    // ── Challenges ──
    async storeChallenge(key, challenge, ttlMs) {
      challenges.set(key, { value: challenge, expiresAt: Date.now() + ttlMs })
    },
    async getChallenge(key) {
      const entry = challenges.get(key)
      if (isExpired(entry)) {
        challenges.delete(key)
        return null
      }
      return entry!.value
    },
    async deleteChallenge(key) {
      challenges.delete(key)
    },

    // ── Magic Links ──
    async storeMagicLink(token, email, ttlMs) {
      magicLinks.set(token, { value: { email }, expiresAt: Date.now() + ttlMs })
    },
    async getMagicLink(token) {
      const entry = magicLinks.get(token)
      if (isExpired(entry)) {
        magicLinks.delete(token)
        return null
      }
      return entry!.value
    },
    async deleteMagicLink(token) {
      magicLinks.delete(token)
    },

    // ── QR Sessions ──
    async createQRSession(session) {
      qrSessions.set(session.id, { ...session })
      return { ...session }
    },
    async getQRSession(id) {
      const session = qrSessions.get(id)
      if (!session) return null
      if (new Date() > session.expiresAt && session.state === 'pending') {
        session.state = 'expired'
      }
      return { ...session }
    },
    async updateQRSession(id, update) {
      const session = qrSessions.get(id)
      if (session) Object.assign(session, update)
    },
  }
}
