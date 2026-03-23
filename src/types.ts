import type {
  AuthenticatorTransportFuture,
  CredentialDeviceType,
  AuthenticationResponseJSON,
  RegistrationResponseJSON,
} from '@simplewebauthn/server'

// ── Core Entities ──

export type MetadataValue =
  | string
  | number
  | boolean
  | null
  | MetadataValue[]
  | { [key: string]: MetadataValue }

export type MetadataObject = { [key: string]: MetadataValue }

/** A registered user account. */
export interface User<TMetadata extends MetadataObject = MetadataObject> {
  id: string
  email?: string
  createdAt: Date
  metadata?: TMetadata
}

/** A WebAuthn credential (passkey) associated with a user. */
export interface Credential<TMetadata extends MetadataObject = MetadataObject> {
  id: string
  userId: string
  publicKey: Uint8Array
  counter: number
  deviceType: CredentialDeviceType
  backedUp: boolean
  transports?: AuthenticatorTransportFuture[]
  /** Human-readable label (e.g. "iPhone", "YubiKey"). */
  label?: string
  createdAt: Date
  metadata?: TMetadata
}

/** An authenticated session bound to a user. */
export interface Session {
  id: string
  token: string
  userId: string
  authMethod: 'passkey' | 'magic-link' | 'qr'
  expiresAt: Date
  createdAt: Date
  /** User-agent string from the request that created the session. */
  userAgent?: string
  /** IP address from the request that created the session. */
  ipAddress?: string
  /** Extra context about how the session was created. */
  authContext?: {
    qrSessionId?: string
  }
}

/** A cross-device login session initiated by QR code scan. */
export interface QRSession {
  id: string
  state: 'created' | 'scanned' | 'challenged' | 'authenticated' | 'expired' | 'cancelled'
  statusToken: string
  userId?: string
  sessionToken?: string
  expiresAt: Date
  createdAt: Date
  scannedAt?: Date
  challengedAt?: Date
  authenticatedAt?: Date
  cancelledAt?: Date
}

// ── Auth Results ──

/** Discriminated union returned from all authentication flows. */
export type AuthResult =
  | { method: 'passkey'; user: User; session: Session }
  | { method: 'magic-link'; user: User; session: Session; isNewUser: boolean }
  | { method: 'qr'; user: User; session: Session }

/** Result of checking whether an email can be linked to a user. */
export type EmailLinkability =
  | { ok: true }
  | { ok: false; reason: 'invalid_email' | 'email_in_use' }

// ── Storage Adapter ──

/**
 * Persistence layer interface. Implement this to use any database.
 *
 * All methods must be safe to call concurrently. Implementations should
 * handle their own serialization of `Date` and `Uint8Array` fields.
 */
export interface StorageAdapter {
  // Users
  createUser(user: User): Promise<User>
  getUserById(id: string): Promise<User | null>
  getUserByEmail(email: string): Promise<User | null>
  updateUser(id: string, update: Partial<Pick<User, 'email' | 'metadata'>>): Promise<User>
  deleteUser(id: string): Promise<void>

  // Credentials (passkeys)
  createCredential(credential: Credential): Promise<Credential>
  getCredentialById(id: string): Promise<Credential | null>
  getCredentialsByUserId(userId: string): Promise<Credential[]>
  updateCredential(id: string, update: Partial<Pick<Credential, 'counter' | 'label' | 'metadata'>>): Promise<void>
  deleteCredential(id: string): Promise<void>

  // Sessions
  createSession(session: Session): Promise<Session>
  getSessionByToken(token: string): Promise<Session | null>
  getSessionsByUserId(userId: string): Promise<Session[]>
  deleteSession(id: string): Promise<void>
  deleteSessionsByUserId(userId: string): Promise<void>

  // Challenge store (short-lived, for WebAuthn)
  storeChallenge(key: string, challenge: string, ttlMs: number): Promise<void>
  getChallenge(key: string): Promise<string | null>
  deleteChallenge(key: string): Promise<void>

  // Magic links
  storeMagicLink(token: string, email: string, ttlMs: number): Promise<void>
  getMagicLink(token: string): Promise<{ email: string } | null>
  deleteMagicLink(token: string): Promise<void>

  // QR sessions
  createQRSession(session: QRSession): Promise<QRSession>
  getQRSession(id: string): Promise<QRSession | null>
  updateQRSession(id: string, update: Partial<QRSession>): Promise<void>
}

// ── Email Adapter ──

/**
 * Email delivery interface. Implement this to send magic link emails.
 *
 * @example
 * ```ts
 * const resendAdapter: EmailAdapter = {
 *   async sendMagicLink(email, url, token) {
 *     await resend.emails.send({ to: email, subject: 'Login', html: `<a href="${url}">Login</a>` })
 *   }
 * }
 * ```
 */
export interface EmailAdapter {
  sendMagicLink(email: string, url: string, token: string): Promise<void>
}

// ── Hooks ──

/** Lifecycle hooks for intercepting auth flows. Return `false` from `before*` hooks to abort. */
export interface AuthHooks {
  beforeRegister?: (ctx: { email?: string }) => Promise<void | false>
  afterRegister?: (ctx: { user: User; credential: Credential }) => Promise<void>
  beforeAuthenticate?: (ctx: { credentialId?: string }) => Promise<void | false>
  afterAuthenticate?: (ctx: { user: User; session: Session }) => Promise<void>
  beforeMagicLink?: (ctx: { email: string }) => Promise<void | false>
  afterMagicLink?: (ctx: { user: User; session: Session; isNewUser: boolean }) => Promise<void>
  beforeQRComplete?: (ctx: { sessionId: string; userId: string }) => Promise<void | false>
  afterQRComplete?: (ctx: { user: User; session: Session }) => Promise<void>
}

// ── Events ──

/** Map of all auth events and their payload types. */
export interface AuthEventMap {
  'user:created': { user: User }
  'user:deleted': { userId: string }
  'session:created': { session: Session; user: User; method: 'passkey' | 'magic-link' | 'qr' }
  'session:revoked': { sessionId: string; userId: string }
  'credential:created': { credential: Credential; user: User }
  'credential:updated': { credentialId: string; userId: string }
  'credential:removed': { credentialId: string; userId: string }
  'magic-link:sent': { email: string }
  'qr:scanned': { sessionId: string }
  'qr:completed': { sessionId: string; user: User }
  'email:linked': { userId: string; email: string }
  'email:unlinked': { userId: string; email: string }
}

/** Typed event handler for a specific auth event. */
export type AuthEventHandler<K extends keyof AuthEventMap> = (event: AuthEventMap[K]) => void

// ── Config ──

/** Configuration for `createAuth()`. */
export interface AuthConfig<TEmail extends EmailAdapter | undefined = undefined> {
  /** Relying party name shown during passkey prompts. */
  rpName: string
  /** Relying party ID — typically the domain (e.g. "example.com"). */
  rpID: string
  /** Expected origin(s) for WebAuthn verification. */
  origin: string | string[]
  /** Storage adapter for persistence. */
  storage: StorageAdapter
  /** Email adapter — enables magic link auth when provided. */
  email?: TEmail
  /** Base URL for magic link verification. Required if `email` is set. */
  magicLinkURL?: TEmail extends EmailAdapter ? string : string | undefined
  /** Session TTL in ms. Default: 7 days. */
  sessionTTL?: number
  /** WebAuthn challenge TTL in ms. Default: 60s. */
  challengeTTL?: number
  /** Magic link token TTL in ms. Default: 15 minutes. */
  magicLinkTTL?: number
  /** QR session TTL in ms. Default: 5 minutes. */
  qrSessionTTL?: number
  /** Custom ID generator. Default: `crypto.randomUUID()`. */
  generateId?: () => string
  /** Lifecycle hooks. */
  hooks?: AuthHooks
}

// ── Magic Link conditional methods ──

/** Methods only available when an `EmailAdapter` is configured. */
export interface MagicLinkMethods {
  /** Send a magic link email. Throws if email format is invalid. */
  sendMagicLink(params: { email: string }): Promise<{ sent: true }>
  /** Verify a magic link token and create a session. Single-use — token is consumed. */
  verifyMagicLink(params: { token: string }): Promise<AuthResult & { method: 'magic-link' }>
}

// ── Client types ──

/**
 * Client configuration. Provide a `request` function that handles
 * transport to your server (fetch, tRPC, WebSocket, etc.).
 */
export interface ClientConfig {
  request: <T = unknown>(endpoint: string, body?: unknown) => Promise<T>
}

/** Status of a QR cross-device login session. */
export interface QRSessionStatus {
  state: QRSession['state']
  session?: { token: string; expiresAt: string }
}

// ── Re-export WebAuthn types for convenience ──

export type { AuthenticationResponseJSON, RegistrationResponseJSON }
