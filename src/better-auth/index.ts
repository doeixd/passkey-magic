import { createAuth } from '../server/index.js'
import type { StorageAdapter, EmailAdapter, Credential, QRSession } from '../types.js'
import type { BetterAuthPlugin } from 'better-auth'
import type { BetterAuthClientPlugin } from 'better-auth'
import { createAuthEndpoint, sessionMiddleware } from 'better-auth/api'
import { setSessionCookie } from 'better-auth/cookies'
import { APIError } from 'better-auth/api'
import * as z from 'zod'

// ── Types ──

export interface PasskeyMagicPluginOptions {
  rpName: string
  rpID: string
  origin: string | string[]
  email?: EmailAdapter
  magicLinkURL?: string
  challengeTTL?: number
  magicLinkTTL?: number
  qrSessionTTL?: number
}

type AuthInstance = ReturnType<typeof createAuth>

// ── Schema ──

const passkeyCredentialSchema = {
  fields: {
    userId: {
      type: 'string' as const,
      required: true,
      references: { model: 'user', field: 'id', onDelete: 'cascade' as const },
    },
    publicKey: { type: 'string' as const, required: true },
    counter: { type: 'number' as const, required: true },
    deviceType: { type: 'string' as const, required: true },
    backedUp: { type: 'boolean' as const, required: true },
    transports: { type: 'string' as const, required: false },
    label: { type: 'string' as const, required: false },
    createdAt: { type: 'date' as const, required: true },
  },
}

const qrSessionSchema = {
  fields: {
    state: { type: 'string' as const, required: true },
    userId: { type: 'string' as const, required: false },
    sessionToken: { type: 'string' as const, required: false },
    expiresAt: { type: 'date' as const, required: true },
    createdAt: { type: 'date' as const, required: true },
  },
}

const passkeyChallengeSchema = {
  fields: {
    key: { type: 'string' as const, required: true, unique: true },
    challenge: { type: 'string' as const, required: true },
    expiresAt: { type: 'date' as const, required: true },
  },
}

const magicLinkTokenSchema = {
  fields: {
    email: { type: 'string' as const, required: true },
    expiresAt: { type: 'date' as const, required: true },
  },
}

// ── Helpers ──

function base64urlEncode(buf: Uint8Array): string {
  let str = ''
  for (let i = 0; i < buf.length; i++) {
    str += String.fromCharCode(buf[i])
  }
  return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

function base64urlDecode(str: string): Uint8Array {
  const padded = str.replace(/-/g, '+').replace(/_/g, '/') + '=='.slice(0, (4 - (str.length % 4)) % 4)
  const binary = atob(padded)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i)
  }
  return bytes
}

// ── Storage Bridge ──

interface BetterAuthAdapter {
  create: <T extends Record<string, any>>(data: {
    model: string
    data: Record<string, any>
    forceAllowId?: boolean
  }) => Promise<T>
  findOne: <T>(data: {
    model: string
    where: Array<{ field: string; value: any; operator?: string }>
  }) => Promise<T | null>
  findMany: <T>(data: {
    model: string
    where?: Array<{ field: string; value: any; operator?: string }>
    limit?: number
  }) => Promise<T[]>
  update: <T>(data: {
    model: string
    where: Array<{ field: string; value: any; operator?: string }>
    update: Record<string, any>
  }) => Promise<T | null>
  delete: (data: {
    model: string
    where: Array<{ field: string; value: any; operator?: string }>
  }) => Promise<void>
  deleteMany: (data: {
    model: string
    where: Array<{ field: string; value: any; operator?: string }>
  }) => Promise<number>
}

function createBridgedStorage(adapter: BetterAuthAdapter): StorageAdapter {
  // In-memory session store — passkey-magic creates its own sessions internally,
  // but we discard them and create proper better-auth sessions in the endpoint handlers.
  // Storing passkey-magic sessions in-memory avoids polluting better-auth's session table
  // with orphaned entries and avoids schema mismatches (e.g. missing updatedAt).
  const pmSessions = new Map<string, any>()
  const pmSessionsByToken = new Map<string, string>() // token → id
  const pmSessionsByUser = new Map<string, Set<string>>() // userId → Set<id>

  return {
    // ── Users ──
    async createUser(user) {
      const now = new Date()
      await adapter.create({
        model: 'user',
        data: {
          id: user.id,
          email: user.email ?? null,
          name: '',
          emailVerified: false,
          createdAt: user.createdAt ?? now,
          updatedAt: now,
        },
        forceAllowId: true,
      })
      return user
    },
    async getUserById(id) {
      const row = await adapter.findOne<any>({
        model: 'user',
        where: [{ field: 'id', value: id }],
      })
      if (!row) return null
      return { id: row.id, email: row.email ?? undefined, createdAt: new Date(row.createdAt) }
    },
    async getUserByEmail(email) {
      const row = await adapter.findOne<any>({
        model: 'user',
        where: [{ field: 'email', value: email }],
      })
      if (!row) return null
      return { id: row.id, email: row.email ?? undefined, createdAt: new Date(row.createdAt) }
    },
    async updateUser(id, update) {
      const row = await adapter.update<any>({
        model: 'user',
        where: [{ field: 'id', value: id }],
        update,
      })
      if (!row) throw new Error('User not found')
      return { id: row.id, email: row.email ?? undefined, createdAt: new Date(row.createdAt) }
    },
    async deleteUser(id) {
      await adapter.delete({ model: 'user', where: [{ field: 'id', value: id }] })
    },

    // ── Credentials ──
    async createCredential(credential) {
      await adapter.create({
        model: 'passkeyCredential',
        data: {
          id: credential.id,
          userId: credential.userId,
          publicKey: base64urlEncode(credential.publicKey),
          counter: credential.counter,
          deviceType: credential.deviceType,
          backedUp: credential.backedUp,
          transports: credential.transports ? JSON.stringify(credential.transports) : null,
          label: credential.label ?? null,
          createdAt: credential.createdAt,
        },
        forceAllowId: true,
      })
      return credential
    },
    async getCredentialById(id) {
      try {
        const row = await adapter.findOne<any>({
          model: 'passkeyCredential',
          where: [{ field: 'id', value: id }],
        })
        if (!row) return null
        return rowToCredential(row)
      } catch {
        return null
      }
    },
    async getCredentialsByUserId(userId) {
      try {
        const rows = await adapter.findMany<any>({
          model: 'passkeyCredential',
          where: [{ field: 'userId', value: userId }],
        })
        return rows.map(rowToCredential)
      } catch {
        // Table may not exist yet (e.g. memory adapter before first write)
        return []
      }
    },
    async updateCredential(id, update) {
      await adapter.update({
        model: 'passkeyCredential',
        where: [{ field: 'id', value: id }],
        update,
      })
    },
    async deleteCredential(id) {
      await adapter.delete({ model: 'passkeyCredential', where: [{ field: 'id', value: id }] })
    },

    // ── Sessions (in-memory) ──
    // passkey-magic sessions are stored in-memory only. The endpoint handlers
    // create proper better-auth sessions via internalAdapter.createSession().
    async createSession(session) {
      pmSessions.set(session.id, session)
      pmSessionsByToken.set(session.token, session.id)
      const userSet = pmSessionsByUser.get(session.userId) ?? new Set()
      userSet.add(session.id)
      pmSessionsByUser.set(session.userId, userSet)
      return session
    },
    async getSessionByToken(token) {
      const id = pmSessionsByToken.get(token)
      if (!id) return null
      const session = pmSessions.get(id)
      if (!session) return null
      if (new Date(session.expiresAt) < new Date()) {
        pmSessions.delete(id)
        pmSessionsByToken.delete(token)
        return null
      }
      return { ...session }
    },
    async getSessionsByUserId(userId) {
      const ids = pmSessionsByUser.get(userId)
      if (!ids) return []
      const result: any[] = []
      for (const id of ids) {
        const s = pmSessions.get(id)
        if (s) result.push({ ...s })
      }
      return result
    },
    async deleteSession(id) {
      const session = pmSessions.get(id)
      if (session) {
        pmSessionsByToken.delete(session.token)
        pmSessionsByUser.get(session.userId)?.delete(id)
      }
      pmSessions.delete(id)
    },
    async deleteSessionsByUserId(userId) {
      const ids = pmSessionsByUser.get(userId)
      if (ids) {
        for (const id of ids) {
          const s = pmSessions.get(id)
          if (s) pmSessionsByToken.delete(s.token)
          pmSessions.delete(id)
        }
        pmSessionsByUser.delete(userId)
      }
    },

    // ── Challenges ──
    async storeChallenge(key, challenge, ttlMs) {
      const expiresAt = new Date(Date.now() + ttlMs)
      // Try to delete any existing challenge with this key first
      try {
        await adapter.delete({ model: 'passkeyChallenge', where: [{ field: 'key', value: key }] })
      } catch { /* ignore if not found */ }
      await adapter.create({
        model: 'passkeyChallenge',
        data: { key, challenge, expiresAt },
      })
    },
    async getChallenge(key) {
      try {
        const row = await adapter.findOne<any>({
          model: 'passkeyChallenge',
          where: [{ field: 'key', value: key }],
        })
        if (!row) return null
        if (new Date(row.expiresAt) < new Date()) {
          await adapter.delete({ model: 'passkeyChallenge', where: [{ field: 'key', value: key }] })
          return null
        }
        return row.challenge
      } catch {
        return null
      }
    },
    async deleteChallenge(key) {
      await adapter.delete({ model: 'passkeyChallenge', where: [{ field: 'key', value: key }] })
    },

    // ── Magic Links ──
    async storeMagicLink(token, email, ttlMs) {
      const expiresAt = new Date(Date.now() + ttlMs)
      await adapter.create({
        model: 'magicLinkToken',
        data: { id: token, email, expiresAt },
        forceAllowId: true,
      })
    },
    async getMagicLink(token) {
      try {
        const row = await adapter.findOne<any>({
          model: 'magicLinkToken',
          where: [{ field: 'id', value: token }],
        })
        if (!row) return null
        if (new Date(row.expiresAt) < new Date()) {
          await adapter.delete({ model: 'magicLinkToken', where: [{ field: 'id', value: token }] })
          return null
        }
        return { email: row.email }
      } catch {
        return null
      }
    },
    async deleteMagicLink(token) {
      await adapter.delete({ model: 'magicLinkToken', where: [{ field: 'id', value: token }] })
    },

    // ── QR Sessions ──
    async createQRSession(session) {
      await adapter.create({
        model: 'qrSession',
        data: {
          id: session.id,
          state: session.state,
          userId: session.userId ?? null,
          sessionToken: session.sessionToken ?? null,
          expiresAt: session.expiresAt,
          createdAt: session.createdAt,
        },
        forceAllowId: true,
      })
      return session
    },
    async getQRSession(id) {
      try {
        const row = await adapter.findOne<any>({
          model: 'qrSession',
          where: [{ field: 'id', value: id }],
        })
        if (!row) return null
        return {
          id: row.id,
          state: row.state,
          userId: row.userId ?? undefined,
          sessionToken: row.sessionToken ?? undefined,
          expiresAt: new Date(row.expiresAt),
          createdAt: new Date(row.createdAt),
        }
      } catch {
        return null
      }
    },
    async updateQRSession(id, update) {
      await adapter.update({
        model: 'qrSession',
        where: [{ field: 'id', value: id }],
        update,
      })
    },
  }
}

function rowToCredential(row: any): Credential {
  return {
    id: row.id,
    userId: row.userId,
    publicKey: base64urlDecode(row.publicKey),
    counter: row.counter,
    deviceType: row.deviceType,
    backedUp: row.backedUp,
    transports: row.transports ? JSON.parse(row.transports) : undefined,
    label: row.label ?? undefined,
    createdAt: new Date(row.createdAt),
  }
}

// ── Session helper ──

async function createBetterAuthSession(
  ctx: any,
  userId: string,
): Promise<{ session: any; user: any }> {
  const session = await ctx.context.internalAdapter.createSession(userId)
  if (!session) {
    throw new APIError('INTERNAL_SERVER_ERROR', { message: 'Failed to create session' })
  }
  const user = await ctx.context.internalAdapter.findUserById(userId)
  if (!user) {
    throw new APIError('INTERNAL_SERVER_ERROR', { message: 'User not found after auth' })
  }
  await setSessionCookie(ctx, { session, user })
  return { session, user }
}

// ── Ensure user exists in better-auth ──

async function ensureBetterAuthUser(
  ctx: any,
  userId: string,
  email?: string,
): Promise<void> {
  const existing = await ctx.context.internalAdapter.findUserById(userId)
  if (!existing) {
    await ctx.context.internalAdapter.createUser({
      id: userId,
      email: email ?? '',
      name: '',
      emailVerified: !!email,
    })
  }
}

// ── Plugin ──

export function passkeyMagicPlugin(options: PasskeyMagicPluginOptions) {
  let _auth: AuthInstance | null = null

  function getAuth(ctx: any): AuthInstance {
    if (!_auth) {
      const storage = createBridgedStorage(ctx.context.adapter)
      _auth = createAuth({
        rpName: options.rpName,
        rpID: options.rpID,
        origin: options.origin,
        storage,
        email: options.email,
        magicLinkURL: options.magicLinkURL,
        challengeTTL: options.challengeTTL,
        magicLinkTTL: options.magicLinkTTL,
        qrSessionTTL: options.qrSessionTTL,
      } as any)
    }
    return _auth
  }

  return {
    id: 'passkey-magic',
    schema: {
      passkeyCredential: passkeyCredentialSchema,
      qrSession: qrSessionSchema,
      passkeyChallenge: passkeyChallengeSchema,
      magicLinkToken: magicLinkTokenSchema,
    },
    endpoints: {
      // ── Passkey Registration ──
      passkeyMagicRegisterOptions: createAuthEndpoint(
        '/passkey-magic/register/options',
        {
          method: 'POST',
          body: z.object({
            userId: z.string().optional(),
            email: z.string().optional(),
            userName: z.string().optional(),
          }),
        },
        async (ctx) => {
          const auth = getAuth(ctx)
          const result = await auth.generateRegistrationOptions({
            userId: ctx.body.userId,
            email: ctx.body.email,
            userName: ctx.body.userName,
          })
          return ctx.json(result)
        },
      ),

      passkeyMagicRegisterVerify: createAuthEndpoint(
        '/passkey-magic/register/verify',
        {
          method: 'POST',
          body: z.object({
            userId: z.string(),
            response: z.any(),
          }),
        },
        async (ctx) => {
          const auth = getAuth(ctx)
          const result = await auth.verifyRegistration({
            userId: ctx.body.userId,
            response: ctx.body.response,
          })
          await ensureBetterAuthUser(ctx, result.user.id, result.user.email)
          const { session, user } = await createBetterAuthSession(ctx, result.user.id)
          return ctx.json({ session, user, credential: result.credential })
        },
      ),

      // ── Passkey Authentication ──
      passkeyMagicAuthenticateOptions: createAuthEndpoint(
        '/passkey-magic/authenticate/options',
        {
          method: 'POST',
          body: z.object({
            userId: z.string().optional(),
          }).optional(),
        },
        async (ctx) => {
          const auth = getAuth(ctx)
          const result = await auth.generateAuthenticationOptions({
            userId: ctx.body?.userId,
          })
          return ctx.json(result)
        },
      ),

      passkeyMagicAuthenticateVerify: createAuthEndpoint(
        '/passkey-magic/authenticate/verify',
        {
          method: 'POST',
          body: z.object({
            response: z.any(),
          }),
        },
        async (ctx) => {
          const auth = getAuth(ctx)
          const result = await auth.verifyAuthentication({
            response: ctx.body.response,
          })
          const { session, user } = await createBetterAuthSession(ctx, result.user.id)
          return ctx.json({ session, user })
        },
      ),

      // ── Add Passkey (authenticated) ──
      passkeyMagicAddOptions: createAuthEndpoint(
        '/passkey-magic/add/options',
        {
          method: 'POST',
          use: [sessionMiddleware],
          body: z.object({
            userName: z.string().optional(),
          }).optional(),
        },
        async (ctx) => {
          const auth = getAuth(ctx)
          const userId = ctx.context.session.user.id
          const result = await auth.addPasskey({
            userId,
            userName: ctx.body?.userName,
          })
          return ctx.json(result)
        },
      ),

      passkeyMagicAddVerify: createAuthEndpoint(
        '/passkey-magic/add/verify',
        {
          method: 'POST',
          use: [sessionMiddleware],
          body: z.object({
            response: z.any(),
          }),
        },
        async (ctx) => {
          const auth = getAuth(ctx)
          const userId = ctx.context.session.user.id
          const result = await auth.verifyAddPasskey({
            userId,
            response: ctx.body.response,
          })
          return ctx.json(result)
        },
      ),

      // ── Credential Management (authenticated) ──
      passkeyMagicCredentials: createAuthEndpoint(
        '/passkey-magic/credentials',
        {
          method: 'GET',
          use: [sessionMiddleware],
        },
        async (ctx) => {
          const auth = getAuth(ctx)
          const userId = ctx.context.session.user.id
          const credentials = await auth.getUserCredentials(userId)
          return ctx.json({ credentials })
        },
      ),

      passkeyMagicCredentialsUpdate: createAuthEndpoint(
        '/passkey-magic/credentials/update',
        {
          method: 'POST',
          use: [sessionMiddleware],
          body: z.object({
            credentialId: z.string(),
            label: z.string(),
          }),
        },
        async (ctx) => {
          const auth = getAuth(ctx)
          await auth.updateCredential({
            credentialId: ctx.body.credentialId,
            label: ctx.body.label,
          })
          return ctx.json({ success: true })
        },
      ),

      passkeyMagicCredentialsRemove: createAuthEndpoint(
        '/passkey-magic/credentials/remove',
        {
          method: 'POST',
          use: [sessionMiddleware],
          body: z.object({
            credentialId: z.string(),
          }),
        },
        async (ctx) => {
          const auth = getAuth(ctx)
          await auth.removeCredential(ctx.body.credentialId)
          return ctx.json({ success: true })
        },
      ),

      // ── QR Cross-Device ──
      passkeyMagicQrCreate: createAuthEndpoint(
        '/passkey-magic/qr/create',
        { method: 'POST' },
        async (ctx) => {
          const auth = getAuth(ctx)
          const result = await auth.createQRSession()
          return ctx.json(result)
        },
      ),

      passkeyMagicQrStatus: createAuthEndpoint(
        '/passkey-magic/qr/status',
        {
          method: 'GET',
          query: z.object({
            sessionId: z.string(),
          }),
        },
        async (ctx) => {
          const auth = getAuth(ctx)
          const result = await auth.getQRSessionStatus(ctx.query.sessionId)
          return ctx.json(result)
        },
      ),

      passkeyMagicQrScanned: createAuthEndpoint(
        '/passkey-magic/qr/scanned',
        {
          method: 'POST',
          body: z.object({
            sessionId: z.string(),
          }),
        },
        async (ctx) => {
          const auth = getAuth(ctx)
          await auth.markQRSessionScanned(ctx.body.sessionId)
          return ctx.json({ success: true })
        },
      ),

      passkeyMagicQrComplete: createAuthEndpoint(
        '/passkey-magic/qr/complete',
        {
          method: 'POST',
          body: z.object({
            sessionId: z.string(),
            response: z.any(),
          }),
        },
        async (ctx) => {
          const auth = getAuth(ctx)
          const result = await auth.completeQRSession({
            sessionId: ctx.body.sessionId,
            response: ctx.body.response,
          })
          const { session, user } = await createBetterAuthSession(ctx, result.user.id)
          // Update the QR session record with the better-auth session token
          // so the desktop polling /qr/status gets a valid BA session token.
          await ctx.context.adapter.update({
            model: 'qrSession',
            where: [{ field: 'id', value: ctx.body.sessionId }],
            update: { sessionToken: session.token },
          })
          return ctx.json({ session, user })
        },
      ),

      // ── Magic Link ──
      passkeyMagicMagicLinkSend: createAuthEndpoint(
        '/passkey-magic/magic-link/send',
        {
          method: 'POST',
          body: z.object({
            email: z.string(),
          }),
        },
        async (ctx) => {
          const auth = getAuth(ctx)
          if (!('sendMagicLink' in auth)) {
            throw new APIError('BAD_REQUEST', { message: 'Magic links not configured' })
          }
          const result = await (auth as any).sendMagicLink({ email: ctx.body.email })
          return ctx.json(result)
        },
      ),

      passkeyMagicMagicLinkVerify: createAuthEndpoint(
        '/passkey-magic/magic-link/verify',
        {
          method: 'POST',
          body: z.object({
            token: z.string(),
          }),
        },
        async (ctx) => {
          const auth = getAuth(ctx)
          if (!('verifyMagicLink' in auth)) {
            throw new APIError('BAD_REQUEST', { message: 'Magic links not configured' })
          }
          const result = await (auth as any).verifyMagicLink({ token: ctx.body.token })
          await ensureBetterAuthUser(ctx, result.user.id, result.user.email)
          const { session, user } = await createBetterAuthSession(ctx, result.user.id)
          return ctx.json({ session, user, isNewUser: result.isNewUser })
        },
      ),
    },
  } satisfies BetterAuthPlugin
}
