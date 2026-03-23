import type { Storage } from 'unstorage'
import type { Credential, MetadataObject, QRSession, Session, StorageAdapter, User } from '../types.js'

/** Options for the unstorage adapter. */
export interface UnstorageAdapterOptions {
  /** Key prefix for all auth data. Defaults to `"auth"`. */
  base?: string
}

/**
 * Storage adapter backed by [unstorage](https://unstorage.unjs.io).
 * Works with any unstorage driver (memory, redis, fs, cloudflare-kv, etc.).
 *
 * Key schema:
 * ```
 * {base}:user:{id}              → User
 * {base}:user-email:{email}     → userId (secondary index)
 * {base}:cred:{id}              → Credential
 * {base}:user-creds:{userId}    → credentialId[] (index)
 * {base}:session:{id}           → Session
 * {base}:session-token:{token}  → sessionId (secondary index)
 * {base}:user-sessions:{userId} → sessionId[] (index)
 * {base}:challenge:{key}        → { challenge, expiresAt }
 * {base}:magic-link:{token}     → { email, expiresAt }
 * {base}:qr:{id}                → QRSession
 * ```
 */
export function unstorageAdapter<
  TUserMetadata extends MetadataObject = MetadataObject,
  TCredentialMetadata extends MetadataObject = MetadataObject,
>(
  storage: Storage,
  options: UnstorageAdapterOptions = {},
): StorageAdapter<TUserMetadata, TCredentialMetadata> {
  const base = options.base ?? 'auth'
  const k = (key: string) => `${base}:${key}`

  function serialize<T>(obj: T): T {
    return JSON.parse(JSON.stringify(obj))
  }

  function deserializeUser(raw: Record<string, unknown> | null): User<TUserMetadata> | null {
    if (!raw) return null
    return {
      ...raw,
      createdAt: new Date(raw.createdAt as string),
      metadata: raw.metadata as User<TUserMetadata>['metadata'] | undefined,
    } as User<TUserMetadata>
  }

  function deserializeCredential(raw: Record<string, unknown> | null): Credential<TCredentialMetadata> | null {
    if (!raw) return null
    const pk = raw.publicKey as Record<string, number>
    return {
      ...raw,
      publicKey: new Uint8Array(Object.values(pk)),
      createdAt: new Date(raw.createdAt as string),
      metadata: raw.metadata as Credential<TCredentialMetadata>['metadata'] | undefined,
    } as Credential<TCredentialMetadata>
  }

  function deserializeSession(raw: Record<string, unknown> | null): Session | null {
    if (!raw) return null
    return {
      ...raw,
      expiresAt: new Date(raw.expiresAt as string),
      createdAt: new Date(raw.createdAt as string),
    } as Session
  }

  function deserializeQRSession(raw: Record<string, unknown> | null): QRSession | null {
    if (!raw) return null
    return {
      ...raw,
      expiresAt: new Date(raw.expiresAt as string),
      createdAt: new Date(raw.createdAt as string),
      scannedAt: raw.scannedAt ? new Date(raw.scannedAt as string) : undefined,
      challengedAt: raw.challengedAt ? new Date(raw.challengedAt as string) : undefined,
      authenticatedAt: raw.authenticatedAt ? new Date(raw.authenticatedAt as string) : undefined,
      cancelledAt: raw.cancelledAt ? new Date(raw.cancelledAt as string) : undefined,
    } as QRSession
  }

  function isTerminalQRState(state: QRSession['state']): boolean {
    return state === 'authenticated' || state === 'expired' || state === 'cancelled'
  }

  const adapter = {
    // ── Users ──
    async createUser(user) {
      await storage.setItem(k(`user:${user.id}`), serialize(user))
      if (user.email) {
        await storage.setItem(k(`user-email:${user.email}`), user.id)
      }
      return { ...user }
    },

    async getUserById(id) {
      const raw = await storage.getItem(k(`user:${id}`)) as Record<string, unknown> | null
      return deserializeUser(raw)
    },

    async getUserByEmail(email) {
      const userId = await storage.getItem<string>(k(`user-email:${email}`))
      if (!userId) return null
      return adapter.getUserById(userId)
    },

    async updateUser(id, update) {
      const raw = await storage.getItem(k(`user:${id}`)) as Record<string, unknown> | null
      if (!raw) throw new Error(`User not found: ${id}`)
      const user = deserializeUser(raw)!
      const oldEmail = user.email

      const updated = { ...user, ...update }
      await storage.setItem(k(`user:${id}`), serialize(updated))

      if (update.email !== undefined && update.email !== oldEmail) {
        if (oldEmail) {
          await storage.removeItem(k(`user-email:${oldEmail}`))
        }
        if (update.email) {
          await storage.setItem(k(`user-email:${update.email}`), id)
        }
      }

      return { ...updated }
    },

    async deleteUser(id) {
      const raw = await storage.getItem(k(`user:${id}`)) as Record<string, unknown> | null
      if (!raw) return
      const user = deserializeUser(raw)!

      // Remove email index
      if (user.email) {
        await storage.removeItem(k(`user-email:${user.email}`))
      }
      await storage.removeItem(k(`user:${id}`))
    },

    // ── Credentials ──
    async createCredential(cred) {
      await storage.setItem(k(`cred:${cred.id}`), serialize(cred))

      const indexKey = k(`user-creds:${cred.userId}`)
      const existing = await storage.getItem<string[]>(indexKey) ?? []
      existing.push(cred.id)
      await storage.setItem(indexKey, existing)

      return { ...cred }
    },

    async getCredentialById(id) {
      const raw = await storage.getItem(k(`cred:${id}`)) as Record<string, unknown> | null
      return deserializeCredential(raw)
    },

    async getCredentialsByUserId(userId) {
      const credIds = await storage.getItem<string[]>(k(`user-creds:${userId}`)) ?? []
      const creds: Credential[] = []
      for (const id of credIds) {
        const cred = await adapter.getCredentialById(id)
        if (cred) creds.push(cred)
      }
      return creds
    },

    async updateCredential(id, update) {
      const raw = await storage.getItem(k(`cred:${id}`)) as Record<string, unknown> | null
      if (!raw) throw new Error(`Credential not found: ${id}`)
      if (update.counter !== undefined) raw.counter = update.counter
      if (update.label !== undefined) raw.label = update.label
      if (update.metadata !== undefined) raw.metadata = update.metadata
      await storage.setItem(k(`cred:${id}`), raw)
    },

    async deleteCredential(id) {
      const raw = await storage.getItem(k(`cred:${id}`)) as Record<string, unknown> | null
      if (!raw) return
      const cred = deserializeCredential(raw)!

      await storage.removeItem(k(`cred:${id}`))

      const indexKey = k(`user-creds:${cred.userId}`)
      const existing = await storage.getItem<string[]>(indexKey) ?? []
      await storage.setItem(indexKey, existing.filter((c) => c !== id))
    },

    // ── Sessions ──
    async createSession(session) {
      await storage.setItem(k(`session:${session.id}`), serialize(session))
      await storage.setItem(k(`session-token:${session.token}`), session.id)

      const indexKey = k(`user-sessions:${session.userId}`)
      const existing = await storage.getItem<string[]>(indexKey) ?? []
      existing.push(session.id)
      await storage.setItem(indexKey, existing)

      return { ...session }
    },

    async getSessionByToken(token) {
      const sessionId = await storage.getItem<string>(k(`session-token:${token}`))
      if (!sessionId) return null

      const raw = await storage.getItem(k(`session:${sessionId}`)) as Record<string, unknown> | null
      const session = deserializeSession(raw)
      if (!session) return null

      if (new Date() > session.expiresAt) {
        await adapter.deleteSession(session.id)
        return null
      }

      return session
    },

    async getSessionsByUserId(userId) {
      const sessionIds = await storage.getItem<string[]>(k(`user-sessions:${userId}`)) ?? []
      const result: Session[] = []
      for (const id of sessionIds) {
        const raw = await storage.getItem(k(`session:${id}`)) as Record<string, unknown> | null
        const session = deserializeSession(raw)
        if (session && new Date() <= session.expiresAt) {
          result.push(session)
        }
      }
      return result
    },

    async deleteSession(id) {
      const raw = await storage.getItem(k(`session:${id}`)) as Record<string, unknown> | null
      if (!raw) return
      const session = deserializeSession(raw)!

      await storage.removeItem(k(`session:${id}`))
      await storage.removeItem(k(`session-token:${session.token}`))

      const indexKey = k(`user-sessions:${session.userId}`)
      const existing = await storage.getItem<string[]>(indexKey) ?? []
      await storage.setItem(indexKey, existing.filter((s) => s !== id))
    },

    async deleteSessionsByUserId(userId) {
      const sessionIds = await storage.getItem<string[]>(k(`user-sessions:${userId}`)) ?? []
      for (const id of sessionIds) {
        const raw = await storage.getItem(k(`session:${id}`)) as Record<string, unknown> | null
        if (raw) {
          const session = deserializeSession(raw)!
          await storage.removeItem(k(`session:${id}`))
          await storage.removeItem(k(`session-token:${session.token}`))
        }
      }
      await storage.setItem(k(`user-sessions:${userId}`), [])
    },

    // ── Challenges ──
    async storeChallenge(key, challenge, ttlMs) {
      await storage.setItem(k(`challenge:${key}`), { challenge, expiresAt: Date.now() + ttlMs })
    },

    async getChallenge(key) {
      const raw = await storage.getItem<{ challenge: string; expiresAt: number }>(k(`challenge:${key}`))
      if (!raw) return null
      if (Date.now() > raw.expiresAt) {
        await storage.removeItem(k(`challenge:${key}`))
        return null
      }
      return raw.challenge
    },

    async deleteChallenge(key) {
      await storage.removeItem(k(`challenge:${key}`))
    },

    // ── Magic Links ──
    async storeMagicLink(token, email, ttlMs) {
      await storage.setItem(k(`magic-link:${token}`), { email, expiresAt: Date.now() + ttlMs })
    },

    async getMagicLink(token) {
      const raw = await storage.getItem<{ email: string; expiresAt: number }>(k(`magic-link:${token}`))
      if (!raw) return null
      if (Date.now() > raw.expiresAt) {
        await storage.removeItem(k(`magic-link:${token}`))
        return null
      }
      return { email: raw.email }
    },

    async deleteMagicLink(token) {
      await storage.removeItem(k(`magic-link:${token}`))
    },

    // ── QR Sessions ──
    async createQRSession(session) {
      await storage.setItem(k(`qr:${session.id}`), serialize(session))
      return { ...session }
    },

    async getQRSession(id) {
      const raw = await storage.getItem(k(`qr:${id}`)) as Record<string, unknown> | null
      const session = deserializeQRSession(raw)
      if (!session) return null

      if (new Date() > session.expiresAt && !isTerminalQRState(session.state)) {
        session.state = 'expired'
      }

      return session
    },

    async updateQRSession(id, update) {
      const raw = await storage.getItem(k(`qr:${id}`)) as Record<string, unknown> | null
      if (!raw) return
      Object.assign(raw, serialize(update))
      await storage.setItem(k(`qr:${id}`), raw)
    },
  } as StorageAdapter<TUserMetadata, TCredentialMetadata>

  return adapter
}
