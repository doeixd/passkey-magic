import type {
  AuthConfig,
  AuthEventHandler,
  AuthEventMap,
  AuthResult,
  Credential,
  EmailLinkability,
  EmailAdapter,
  MagicLinkMethods,
  QRSessionStatus,
  RegistrationResponseJSON,
  AuthenticationResponseJSON,
  Session,
  User,
} from '../types.js'
import { isValidEmail } from '../crypto.js'
import { AuthEmitter } from '../events.js'
import { createSessionManager } from './session.js'
import { createPasskeyManager } from './passkey.js'
import { createMagicLinkManager } from './magic-link.js'
import { createQRSessionManager } from './qr-session.js'
import { createHandler } from './handler.js'

export interface PasskeyNamespace {
  register: {
    start(params: { userId?: string; email?: string; userName?: string }): Promise<{
      options: PublicKeyCredentialCreationOptionsJSON
      userId: string
    }>
    finish(params: {
      userId: string
      response: RegistrationResponseJSON
    }): Promise<AuthResult & { method: 'passkey'; credential: Credential }>
  }
  signIn: {
    start(params?: { userId?: string }): Promise<{ options: PublicKeyCredentialRequestOptionsJSON }>
    finish(params: {
      response: AuthenticationResponseJSON
    }): Promise<AuthResult & { method: 'passkey' }>
  }
  add: {
    start(params: { userId: string; userName?: string }): Promise<{
      options: PublicKeyCredentialCreationOptionsJSON
    }>
    finish(params: { userId: string; response: RegistrationResponseJSON }): Promise<{ credential: Credential }>
  }
  list(userId: string): Promise<Credential[]>
  update(params: { credentialId: string; label?: string; metadata?: Credential['metadata'] }): Promise<void>
  remove(credentialId: string): Promise<void>
}

export interface QRNamespace {
  create(): Promise<{ sessionId: string }>
  getStatus(sessionId: string): Promise<QRSessionStatus>
  markScanned(sessionId: string): Promise<void>
  complete(params: {
    sessionId: string
    response: AuthenticationResponseJSON
  }): Promise<AuthResult & { method: 'qr' }>
  cancel(sessionId: string): Promise<void>
}

export interface MagicLinkNamespace {
  send(params: { email: string }): Promise<{ sent: true }>
  verify(params: { token: string }): Promise<AuthResult & { method: 'magic-link' }>
}

export interface AccountNamespace {
  get(userId: string): Promise<User | null>
  getByEmail(email: string): Promise<User | null>
  isEmailAvailable(email: string): Promise<boolean>
  canLinkEmail(params: { userId: string; email: string }): Promise<EmailLinkability>
  updateMetadata(params: { userId: string; metadata?: User['metadata'] }): Promise<{ user: User }>
  linkEmail(params: { userId: string; email: string }): Promise<{ user: User }>
  unlinkEmail(params: { userId: string }): Promise<{ user: User }>
  delete(userId: string): Promise<void>
}

// ── Base methods (always available) ──

/** Methods available on every `createAuth()` instance regardless of config. */
export interface BaseAuthMethods {
  /** High-level passkey namespace. */
  passkeys: PasskeyNamespace

  /** High-level QR namespace. */
  qr: QRNamespace

  /** High-level account and identity namespace. */
  accounts: AccountNamespace

  // ── Passkey Registration ──

  /**
   * Generate WebAuthn registration options. Send the `options` to the browser.
   * If `userId` is omitted, a new ID is generated.
   */
  generateRegistrationOptions(params: {
    userId?: string
    email?: string
    userName?: string
  }): Promise<{ options: PublicKeyCredentialCreationOptionsJSON; userId: string }>

  /**
   * Verify a WebAuthn registration response and create a session.
   * Creates a new user if the `userId` doesn't exist yet.
   */
  verifyRegistration(params: {
    userId: string
    response: RegistrationResponseJSON
  }): Promise<AuthResult & { method: 'passkey'; credential: Credential }>

  // ── Passkey Authentication ──

  /** Generate WebAuthn authentication options. Send the `options` to the browser. */
  generateAuthenticationOptions(params?: {
    userId?: string
  }): Promise<{ options: PublicKeyCredentialRequestOptionsJSON }>

  /** Verify a WebAuthn authentication response and create a session. */
  verifyAuthentication(params: {
    response: AuthenticationResponseJSON
  }): Promise<AuthResult & { method: 'passkey' }>

  // ── Passkey Management (authenticated users) ──

  /**
   * Generate registration options for adding a passkey to an existing account.
   * Excludes the user's existing credentials.
   */
  addPasskey(params: {
    userId: string
    userName?: string
  }): Promise<{ options: PublicKeyCredentialCreationOptionsJSON }>

  /**
   * Verify and store a new passkey for an existing user.
   * Does not create a session — the user is already authenticated.
   */
  verifyAddPasskey(params: {
    userId: string
    response: RegistrationResponseJSON
  }): Promise<{ credential: Credential }>

  /**
   * Update a credential's metadata (e.g. label).
   * @throws If the credential doesn't exist.
   */
  updateCredential(params: {
    credentialId: string
    label?: string
    metadata?: Credential['metadata']
  }): Promise<void>

  /** Remove a passkey. Verifies the credential exists and cleans up. */
  removeCredential(credentialId: string): Promise<void>

  /** List all passkeys for a user. */
  getUserCredentials(userId: string): Promise<Credential[]>

  // ── QR Cross-Device ──

  /** Create a new QR login session. Returns a `sessionId` to encode in a QR code. */
  createQRSession(): Promise<{ sessionId: string }>

  /** Poll the status of a QR session. */
  getQRSessionStatus(sessionId: string): Promise<QRSessionStatus>

  /** Mark a QR session as scanned (called from the phone after scanning). */
  markQRSessionScanned(sessionId: string): Promise<void>

  /** Cancel a QR session before it completes. */
  cancelQRSession(sessionId: string): Promise<void>

  /**
   * Complete a QR session — authenticates on the phone, creates a session
   * for the desktop. Called from the phone after passkey auth.
   */
  completeQRSession(params: {
    sessionId: string
    response: AuthenticationResponseJSON
  }): Promise<AuthResult & { method: 'qr' }>

  // ── Session Management ──

  /** Validate a session token. Returns user + session if valid, null if expired/invalid. */
  validateSession(token: string): Promise<{ user: User; session: Session } | null>

  /** List all active sessions for a user. */
  getUserSessions(userId: string): Promise<Session[]>

  /** Revoke a single session by token. */
  revokeSession(token: string): Promise<void>

  /** Revoke a single session by ID. */
  revokeSessionById(sessionId: string): Promise<void>

  /** Revoke all sessions for a user. */
  revokeAllSessions(userId: string): Promise<void>

  // ── Account Management ──

  /** Get a user by ID. Returns `null` if not found. */
  getUser(userId: string): Promise<User | null>

  /**
   * Check if an email is available (not already linked to a user).
   * Useful before showing a registration form.
   */
  isEmailAvailable(email: string): Promise<boolean>

  /** Update account metadata for a user. */
  updateUserMetadata(params: { userId: string; metadata?: User['metadata'] }): Promise<{ user: User }>

  /**
   * Link an email to a user account.
   * @throws If the email is already linked to another user.
   * @throws If the email format is invalid.
   */
  linkEmail(params: { userId: string; email: string }): Promise<{ user: User }>

  /**
   * Unlink the email from a user account.
   * @throws If the user has no email linked.
   */
  unlinkEmail(params: { userId: string }): Promise<{ user: User }>

  /**
   * Delete a user account and all associated data (credentials, sessions).
   * This action is irreversible.
   */
  deleteAccount(userId: string): Promise<void>

  // ── Events ──

  /** Subscribe to typed auth events. Returns an unsubscribe function. */
  on<K extends keyof AuthEventMap>(event: K, handler: AuthEventHandler<K>): () => void

  // ── Handler ──

  /**
   * Create a Web Standard `Request → Response` handler for all auth routes.
   * Works with any framework that speaks `Request`/`Response` (Bun, Deno, CF Workers, Hono, etc.).
   */
  createHandler(opts?: { pathPrefix?: string }): (request: Request) => Promise<Response>
}

// ── Conditional type: adds magic link methods only when email adapter exists ──

/** Full auth instance type. Magic link methods are present only when `EmailAdapter` is configured. */
export type AuthInstance<TEmail> = BaseAuthMethods &
  (TEmail extends EmailAdapter ? MagicLinkMethods & { magicLinks: MagicLinkNamespace } : unknown)

// ── Default TTLs ──

const SEVEN_DAYS = 7 * 24 * 60 * 60 * 1000
const SIXTY_SECONDS = 60 * 1000
const FIFTEEN_MINUTES = 15 * 60 * 1000
const FIVE_MINUTES = 5 * 60 * 1000

// ── Factory ──

/**
 * Create a passkey-magic auth instance.
 *
 * @example
 * ```ts
 * const auth = createAuth({
 *   rpName: 'My App',
 *   rpID: 'example.com',
 *   origin: 'https://example.com',
 *   storage: memoryAdapter(),
 * })
 * ```
 *
 * @example With magic link fallback:
 * ```ts
 * const auth = createAuth({
 *   rpName: 'My App',
 *   rpID: 'example.com',
 *   origin: 'https://example.com',
 *   storage: memoryAdapter(),
 *   email: myEmailAdapter,
 *   magicLinkURL: 'https://example.com/auth/verify',
 * })
 * auth.sendMagicLink({ email: 'user@example.com' }) // ✓ type-safe
 * ```
 */
export function createAuth<TEmail extends EmailAdapter | undefined = undefined>(
  config: AuthConfig<TEmail>,
): AuthInstance<TEmail> {
  const emitter = new AuthEmitter()
  const hooks = config.hooks ?? {}

  const sessions = createSessionManager(config.storage, {
    ttl: config.sessionTTL ?? SEVEN_DAYS,
    generateId: config.generateId,
  })

  const passkeys = createPasskeyManager(config.storage, {
    rpName: config.rpName,
    rpID: config.rpID,
    origin: config.origin,
    challengeTTL: config.challengeTTL ?? SIXTY_SECONDS,
    generateId: config.generateId,
  })

  const qrSessions = createQRSessionManager(config.storage, {
    ttl: config.qrSessionTTL ?? FIVE_MINUTES,
    generateId: config.generateId,
  })

  const base: BaseAuthMethods = {
    passkeys: undefined as unknown as PasskeyNamespace,
    qr: undefined as unknown as QRNamespace,
    accounts: undefined as unknown as AccountNamespace,

    // ── Passkey Registration ──
    async generateRegistrationOptions(params) {
      if (hooks.beforeRegister) {
        const result = await hooks.beforeRegister({ email: params.email })
        if (result === false) throw new Error('Registration blocked by hook')
      }
      return passkeys.generateRegistrationOptions(params)
    },

    async verifyRegistration({ userId, response }) {
      const existingUser = await config.storage.getUserById(userId)
      const { user, credential } = await passkeys.verifyRegistration({ userId, response })

      const session = await sessions.create(user.id, 'passkey')

      if (!existingUser) {
        emitter.emit('user:created', { user })
      }
      emitter.emit('credential:created', { credential, user })
      emitter.emit('session:created', { session, user, method: 'passkey' })

      if (hooks.afterRegister) {
        await hooks.afterRegister({ user, credential })
      }

      return { method: 'passkey' as const, user, session, credential }
    },

    // ── Passkey Authentication ──
    async generateAuthenticationOptions(params) {
      if (hooks.beforeAuthenticate) {
        const result = await hooks.beforeAuthenticate({ credentialId: params?.userId })
        if (result === false) throw new Error('Authentication blocked by hook')
      }
      return passkeys.generateAuthenticationOptions(params)
    },

    async verifyAuthentication({ response }) {
      const { user } = await passkeys.verifyAuthentication({ response })
      const session = await sessions.create(user.id, 'passkey')

      emitter.emit('session:created', { session, user, method: 'passkey' })

      if (hooks.afterAuthenticate) {
        await hooks.afterAuthenticate({ user, session })
      }

      return { method: 'passkey' as const, user, session }
    },

    // ── Passkey Management ──
    async addPasskey({ userId, userName }) {
      const user = await config.storage.getUserById(userId)
      if (!user) throw new Error('User not found')

      const { options } = await passkeys.generateRegistrationOptions({
        userId,
        email: user.email,
        userName: userName ?? user.email ?? userId,
        allowExistingUser: true,
      })

      return { options }
    },

    async verifyAddPasskey({ userId, response }) {
      const { user, credential } = await passkeys.verifyRegistration({ userId, response })
      emitter.emit('credential:created', { credential, user })
      return { credential }
    },

    async updateCredential({ credentialId, label, metadata }) {
      const cred = await config.storage.getCredentialById(credentialId)
      if (!cred) throw new Error('Credential not found')
      if (label === undefined && metadata === undefined) {
        throw new Error('No credential updates provided')
      }
      await config.storage.updateCredential(credentialId, { label, metadata })
      emitter.emit('credential:updated', { credentialId, userId: cred.userId })
    },

    async removeCredential(credentialId) {
      const cred = await config.storage.getCredentialById(credentialId)
      if (!cred) throw new Error('Credential not found')

      // Prevent removing the last passkey if user has no email (they'd be locked out)
      const remaining = await config.storage.getCredentialsByUserId(cred.userId)
      if (remaining.length <= 1) {
        const user = await config.storage.getUserById(cred.userId)
        if (!user?.email) {
          throw new Error('Cannot remove the last passkey — user has no email for recovery')
        }
      }

      await config.storage.deleteCredential(credentialId)
      emitter.emit('credential:removed', { credentialId, userId: cred.userId })
    },

    async getUserCredentials(userId) {
      return config.storage.getCredentialsByUserId(userId)
    },

    // ── QR Cross-Device ──
    async createQRSession() {
      return qrSessions.create()
    },

    async getQRSessionStatus(sessionId) {
      return qrSessions.getStatus(sessionId)
    },

    async markQRSessionScanned(sessionId) {
      await qrSessions.markScanned(sessionId)
      emitter.emit('qr:scanned', { sessionId })
    },

    async cancelQRSession(sessionId) {
      await qrSessions.cancel(sessionId)
    },

    async completeQRSession({ sessionId, response }) {
      await qrSessions.beginChallenge(sessionId)
      const { user } = await passkeys.verifyAuthentication({ response })

      if (hooks.beforeQRComplete) {
        const result = await hooks.beforeQRComplete({ sessionId, userId: user.id })
        if (result === false) throw new Error('QR completion blocked by hook')
      }

      const session = await sessions.create(user.id, 'qr', {
        authContext: { qrSessionId: sessionId },
      })

      await qrSessions.complete(sessionId, user.id, session.token)

      emitter.emit('qr:completed', { sessionId, user })
      emitter.emit('session:created', { session, user, method: 'qr' })

      if (hooks.afterQRComplete) {
        await hooks.afterQRComplete({ user, session })
      }

      return { method: 'qr' as const, user, session }
    },

    // ── Sessions ──
    async validateSession(token) {
      const session = await sessions.validate(token)
      if (!session) return null
      const user = await config.storage.getUserById(session.userId)
      if (!user) return null
      return { user, session }
    },

    async getUserSessions(userId) {
      return sessions.listByUser(userId)
    },

    async revokeSession(token) {
      const session = await sessions.validate(token)
      if (session) {
        await sessions.revoke(session.id)
        emitter.emit('session:revoked', { sessionId: session.id, userId: session.userId })
      }
    },

    async revokeSessionById(sessionId) {
      await sessions.revoke(sessionId)
    },

    async revokeAllSessions(userId) {
      await sessions.revokeAll(userId)
    },

    // ── Account Management ──
    async getUser(userId) {
      return config.storage.getUserById(userId)
    },

    async isEmailAvailable(email) {
      if (!isValidEmail(email)) return false
      const existing = await config.storage.getUserByEmail(email)
      return existing === null
    },

    async updateUserMetadata({ userId, metadata }) {
      const user = await config.storage.updateUser(userId, { metadata })
      return { user }
    },

    async linkEmail({ userId, email }) {
      if (!isValidEmail(email)) {
        throw new Error('Invalid email address')
      }

      const existing = await config.storage.getUserByEmail(email)
      if (existing && existing.id !== userId) {
        throw new Error('Email is already linked to another account')
      }

      const user = await config.storage.updateUser(userId, { email })
      emitter.emit('email:linked', { userId, email })
      return { user }
    },

    async unlinkEmail({ userId }) {
      const user = await config.storage.getUserById(userId)
      if (!user) throw new Error('User not found')
      if (!user.email) throw new Error('User has no email to unlink')

      // Prevent unlinking if user has no passkeys (they'd be locked out)
      const creds = await config.storage.getCredentialsByUserId(userId)
      if (creds.length === 0) {
        throw new Error('Cannot unlink email — user has no passkeys for recovery')
      }

      const oldEmail = user.email
      const updated = await config.storage.updateUser(userId, { email: undefined })
      emitter.emit('email:unlinked', { userId, email: oldEmail })
      return { user: updated }
    },

    async deleteAccount(userId) {
      // Delete all credentials
      const creds = await config.storage.getCredentialsByUserId(userId)
      for (const cred of creds) {
        await config.storage.deleteCredential(cred.id)
      }

      // Delete all sessions
      await config.storage.deleteSessionsByUserId(userId)

      // Delete the user
      await config.storage.deleteUser(userId)

      emitter.emit('user:deleted', { userId })
    },

    // ── Events ──
    on(event, handler) {
      return emitter.on(event, handler)
    },

    // ── Handler ──
    createHandler(opts) {
      return createHandler(this as AuthInstance<EmailAdapter | undefined>, opts)
    },
  }

  base.passkeys = {
    register: {
      start: (params) => base.generateRegistrationOptions(params),
      finish: (params) => base.verifyRegistration(params),
    },
    signIn: {
      start: (params) => base.generateAuthenticationOptions(params),
      finish: (params) => base.verifyAuthentication(params),
    },
    add: {
      start: (params) => base.addPasskey(params),
      finish: (params) => base.verifyAddPasskey(params),
    },
    list: (userId) => base.getUserCredentials(userId),
    update: (params) => base.updateCredential(params),
    remove: (credentialId) => base.removeCredential(credentialId),
  }

  base.qr = {
    create: () => base.createQRSession(),
    getStatus: (sessionId) => base.getQRSessionStatus(sessionId),
    markScanned: (sessionId) => base.markQRSessionScanned(sessionId),
    complete: (params) => base.completeQRSession(params),
    cancel: (sessionId) => base.cancelQRSession(sessionId),
  }

  base.accounts = {
    get: (userId) => base.getUser(userId),
    getByEmail: async (email) => {
      if (!isValidEmail(email)) return null
      return config.storage.getUserByEmail(email)
    },
    isEmailAvailable: (email) => base.isEmailAvailable(email),
    async canLinkEmail({ userId, email }) {
      if (!isValidEmail(email)) {
        return { ok: false, reason: 'invalid_email' as const }
      }
      const existing = await config.storage.getUserByEmail(email)
      if (existing && existing.id !== userId) {
        return { ok: false, reason: 'email_in_use' as const }
      }
      return { ok: true }
    },
    updateMetadata: (params) => base.updateUserMetadata(params),
    linkEmail: (params) => base.linkEmail(params),
    unlinkEmail: (params) => base.unlinkEmail(params),
    delete: (userId) => base.deleteAccount(userId),
  }

  // ── Magic Link (conditional) ──
  if (config.email) {
    const magicLinks = createMagicLinkManager(config.storage, config.email, {
      magicLinkURL: (config as AuthConfig<EmailAdapter>).magicLinkURL!,
      ttl: config.magicLinkTTL ?? FIFTEEN_MINUTES,
      generateId: config.generateId,
    })

    const magicLinkMethods: MagicLinkMethods & { magicLinks: MagicLinkNamespace } = {
      async sendMagicLink({ email }) {
        if (hooks.beforeMagicLink) {
          const result = await hooks.beforeMagicLink({ email })
          if (result === false) throw new Error('Magic link blocked by hook')
        }
        const response = await magicLinks.send({ email })
        emitter.emit('magic-link:sent', { email })
        return response
      },

      async verifyMagicLink({ token }) {
        const { user, isNewUser } = await magicLinks.verify({ token })
        const session = await sessions.create(user.id, 'magic-link')

        if (isNewUser) {
          emitter.emit('user:created', { user })
        }
        emitter.emit('session:created', { session, user, method: 'magic-link' })

        if (hooks.afterMagicLink) {
          await hooks.afterMagicLink({ user, session, isNewUser })
        }

        return { method: 'magic-link' as const, user, session, isNewUser }
      },

      magicLinks: {
        send: (params) => magicLinkMethods.sendMagicLink(params),
        verify: (params) => magicLinkMethods.verifyMagicLink(params),
      },
    }

    Object.assign(base, magicLinkMethods)
  }

  return base as AuthInstance<TEmail>
}

// Re-export types
export type {
  AuthConfig,
  AuthResult,
  Credential,
  EmailAdapter,
  MagicLinkMethods,
  QRSessionStatus,
  Session,
  StorageAdapter,
  User,
  AuthHooks,
  AuthEventMap,
  AuthEventHandler,
  AuthenticationResponseJSON,
  RegistrationResponseJSON,
} from '../types.js'
