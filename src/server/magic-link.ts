import { generateId as defaultGenerateId, generateToken, isValidEmail } from '../crypto.js'
import type { EmailAdapter, StorageAdapter, User } from '../types.js'

/** Internal magic link manager used by `createAuth()`. */
export interface MagicLinkManager {
  send(params: { email: string }): Promise<{ sent: true }>
  verify(params: { token: string }): Promise<{ user: User; isNewUser: boolean }>
}

export function createMagicLinkManager(
  storage: StorageAdapter,
  emailAdapter: EmailAdapter,
  opts: {
    magicLinkURL: string
    ttl: number
    generateId?: () => string
  },
): MagicLinkManager {
  const generateId = opts.generateId ?? defaultGenerateId

  return {
    async send({ email }) {
      if (!isValidEmail(email)) {
        throw new Error('Invalid email address')
      }

      const token = generateToken(32)
      await storage.storeMagicLink(token, email, opts.ttl)

      const url = `${opts.magicLinkURL}?token=${encodeURIComponent(token)}`
      await emailAdapter.sendMagicLink(email, url, token)

      return { sent: true }
    },

    async verify({ token }) {
      if (!token || typeof token !== 'string') {
        throw new Error('Invalid magic link token')
      }

      const entry = await storage.getMagicLink(token)
      if (!entry) {
        throw new Error('Magic link expired or invalid')
      }

      // Single-use: delete immediately
      await storage.deleteMagicLink(token)

      let user = await storage.getUserByEmail(entry.email)
      let isNewUser = false

      if (!user) {
        user = await storage.createUser({
          id: generateId(),
          email: entry.email,
          createdAt: new Date(),
        })
        isNewUser = true
      }

      return { user, isNewUser }
    },
  }
}
