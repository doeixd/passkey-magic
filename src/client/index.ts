import type { ClientConfig, Credential, EmailLinkability, MetadataObject, QRSessionStatus, Session, User } from '../types.js'
import { createClientPasskeyManager } from './passkey.js'
import { createClientQRManager } from './qr.js'
import { createClientMagicLinkManager } from './magic-link.js'

type ClientUser<TUserMetadata extends MetadataObject> = Pick<User<TUserMetadata>, 'id' | 'email' | 'metadata'>

export class AuthClientError extends Error {
  code: 'AUTH_CLIENT_ERROR'
  status?: number
  cause?: unknown

  constructor(message: string, options?: { status?: number; cause?: unknown }) {
    super(message)
    this.name = 'AuthClientError'
    this.code = 'AUTH_CLIENT_ERROR'
    this.status = options?.status
    this.cause = options?.cause
  }
}

export function normalizeAuthClientError(error: unknown): AuthClientError {
  if (error instanceof AuthClientError) return error

  const message =
    typeof error === 'object' && error !== null && 'message' in error && typeof (error as { message: unknown }).message === 'string'
      ? (error as { message: string }).message
      : 'Authentication request failed'

  const status =
    typeof error === 'object' && error !== null && 'status' in error && typeof (error as { status: unknown }).status === 'number'
      ? (error as { status: number }).status
      : undefined

  return new AuthClientError(message, { status, cause: error })
}

/**
 * Client-side auth interface. All methods delegate to the server
 * via the `request` function you provide in config.
 */
export interface PasskeyMagicClient<
  TUserMetadata extends MetadataObject = MetadataObject,
  TCredentialMetadata extends MetadataObject = MetadataObject,
> {
  passkeys: {
    register: (params?: { userId?: string; email?: string; userName?: string }) => Promise<{
      method: 'passkey'
      user: ClientUser<TUserMetadata>
      session: { token: string; expiresAt: string; authMethod: 'passkey'; authContext?: { qrSessionId?: string } }
      credential: { id: string }
    }>
    signIn: (params?: { userId?: string }) => Promise<{
      method: 'passkey'
      user: ClientUser<TUserMetadata>
      session: { token: string; expiresAt: string; authMethod: 'passkey'; authContext?: { qrSessionId?: string } }
    }>
    add: (params?: { userName?: string }) => Promise<{ credential: { id: string } }>
    list(userId?: string): Promise<{ credentials: Credential<TCredentialMetadata>[] }>
    update(params: { credentialId: string; label?: string; metadata?: Credential<TCredentialMetadata>['metadata'] }): Promise<void>
    remove(credentialId: string): Promise<void>
  }

  qr: {
    /** Create a desktop QR session and keep `statusToken` private for polling/cancellation. */
    create(): Promise<{ sessionId: string; statusToken: string; confirmationCode?: string }>
    render(url: string, opts?: { border?: number }): string
    renderText(url: string, opts?: { border?: number }): string
    /** Poll QR status with the desktop-only `statusToken`. */
    poll(sessionId: string, statusToken: string, opts?: { interval?: number; signal?: AbortSignal }): AsyncIterable<QRSessionStatus>
    /** Wait until QR authentication completes or terminally fails. */
    waitForAuthentication(
      sessionId: string,
      statusToken: string,
      opts?: { interval?: number; signal?: AbortSignal; timeoutMs?: number },
    ): Promise<{ token: string; expiresAt: string }>
    /** Confirm a QR session using the desktop-shown short code when enabled. */
    confirm(params: { sessionId: string; confirmationCode: string }): Promise<void>
    complete(params: { sessionId: string; confirmationCode?: string }): Promise<void>
    cancel(params: { sessionId: string; statusToken: string }): Promise<void>
  }

  magicLinks: {
    request(params: { email: string }): Promise<{ sent: true }>
    verify(params: { token: string }): Promise<{
      method: 'magic-link'
      user: ClientUser<TUserMetadata>
      session: { token: string; expiresAt: string; authMethod: 'magic-link'; authContext?: { qrSessionId?: string } }
      isNewUser: boolean
    }>
    extractToken(input: string | URL): string
    verifyURL(params: { url: string | URL }): Promise<{
      method: 'magic-link'
      user: ClientUser<TUserMetadata>
      session: { token: string; expiresAt: string; authMethod: 'magic-link'; authContext?: { qrSessionId?: string } }
      isNewUser: boolean
    }>
  }

  accounts: {
    get(): Promise<{ user: User<TUserMetadata> }>
    isEmailAvailable(email: string): Promise<boolean>
    canLinkEmail(email: string): Promise<EmailLinkability>
    updateMetadata(metadata?: User<TUserMetadata>['metadata']): Promise<{ user: User<TUserMetadata> }>
    linkEmail(email: string): Promise<{ user: User<TUserMetadata> }>
    unlinkEmail(): Promise<{ user: User<TUserMetadata> }>
    delete(): Promise<void>
  }

  // ── Passkey ──

  /** Check if the browser supports WebAuthn. */
  supportsPasskeys(): boolean
  /** Check if the browser supports WebAuthn conditional UI (autofill). */
  supportsAutofill(): Promise<boolean>
  /** Check if a platform authenticator (Touch ID, Windows Hello) is available. */
  hasPlatformAuthenticator(): Promise<boolean>

  /** Register a new passkey and create an account. */
  registerPasskey(params?: {
    userId?: string
    email?: string
    userName?: string
  }): Promise<{
    method: 'passkey'
    user: ClientUser<TUserMetadata>
    session: { token: string; expiresAt: string; authMethod: 'passkey'; authContext?: { qrSessionId?: string } }
    credential: { id: string }
  }>

  /** Sign in with an existing passkey. */
  signInWithPasskey(params?: {
    userId?: string
  }): Promise<{
    method: 'passkey'
    user: ClientUser<TUserMetadata>
    session: { token: string; expiresAt: string; authMethod: 'passkey'; authContext?: { qrSessionId?: string } }
  }>

  // ── Passkey Management ──

  /** Add a passkey to the current account (requires auth). */
  addPasskey(params?: { userName?: string }): Promise<{ credential: { id: string } }>
  /** Update a passkey label. */
  updateCredential(params: { credentialId: string; label?: string; metadata?: Credential<TCredentialMetadata>['metadata'] }): Promise<void>
  /** Remove a passkey. */
  removeCredential(credentialId: string): Promise<void>
  /** List all passkeys for the current user. */
  listCredentials(): Promise<{ credentials: Credential<TCredentialMetadata>[] }>

  // ── QR Cross-Device ──

  /** Create a new QR login session on the server. Keep `statusToken` private on the desktop. */
  createQRSession(): Promise<{ sessionId: string; statusToken: string; confirmationCode?: string }>
  /** Render a URL as an SVG QR code using uqr. */
  renderQR(url: string, opts?: { border?: number }): string
  /** Render a URL as a text QR code using uqr. */
  renderQRText(url: string, opts?: { border?: number }): string
  /**
   * Poll a QR session for status changes.
   * Yields status updates until `authenticated`, `expired`, or `cancelled`.
   * Requires the desktop-only `statusToken` returned from `createQRSession()`.
   */
  pollQRSession(
    sessionId: string,
    statusToken: string,
    opts?: { interval?: number; signal?: AbortSignal },
  ): AsyncIterable<QRSessionStatus>
  /** Wait for QR authentication to succeed or fail terminally. */
  waitForQRSession(
    sessionId: string,
    statusToken: string,
    opts?: { interval?: number; signal?: AbortSignal; timeoutMs?: number },
  ): Promise<{ token: string; expiresAt: string }>
  /** Complete a QR session from the scanning device (authenticates with passkey). */
  confirmQRSession(params: { sessionId: string; confirmationCode: string }): Promise<void>
  completeQRSession(params: { sessionId: string; confirmationCode?: string }): Promise<void>
  /** Cancel a QR session before it completes. */
  cancelQRSession(params: { sessionId: string; statusToken: string }): Promise<void>

  // ── Magic Link ──

  /** Request a magic link email. */
  requestMagicLink(params: { email: string }): Promise<{ sent: true }>
  /** Verify a magic link token and create a session. */
  verifyMagicLink(params: { token: string }): Promise<{
    method: 'magic-link'
    user: ClientUser<TUserMetadata>
    session: { token: string; expiresAt: string; authMethod: 'magic-link'; authContext?: { qrSessionId?: string } }
    isNewUser: boolean
  }>
  /** Extract a magic-link token from a callback URL. */
  extractMagicLinkToken(input: string | URL): string
  /** Verify a magic-link token directly from a callback URL. */
  verifyMagicLinkURL(params: { url: string | URL }): Promise<{
    method: 'magic-link'
    user: ClientUser<TUserMetadata>
    session: { token: string; expiresAt: string; authMethod: 'magic-link'; authContext?: { qrSessionId?: string } }
    isNewUser: boolean
  }>

  // ── Session Management ──

  /** Validate the current session. Returns null if invalid/expired. */
  getSession(): Promise<{ user: User<TUserMetadata>; session: Session } | null>
  /** List all active sessions. */
  listSessions(): Promise<{ sessions: Session[] }>
  /** Revoke the current session (logout). */
  revokeSession(): Promise<void>
  /** Revoke a specific session by ID. */
  revokeSessionById(sessionId: string): Promise<void>
  /** Revoke all sessions (logout everywhere). */
  revokeAllSessions(): Promise<void>

  // ── Account Management ──

  /** Get the current user profile. */
  getAccount(): Promise<{ user: User<TUserMetadata> }>
  /** Check if an email is available. */
  isEmailAvailable(email: string): Promise<boolean>
  /** Update metadata on the current account. */
  updateAccountMetadata(metadata?: User<TUserMetadata>['metadata']): Promise<{ user: User<TUserMetadata> }>
  /** Link an email to the current account. */
  linkEmail(email: string): Promise<{ user: User<TUserMetadata> }>
  /** Unlink the email from the current account. */
  unlinkEmail(): Promise<{ user: User<TUserMetadata> }>
  /** Delete the current account and all data. */
  deleteAccount(): Promise<void>
}

/**
 * Create a passkey-magic client.
 *
 * @example
 * ```ts
 * const client = createClient({
 *   request: async (endpoint, body) => {
 *     const res = await fetch(`/api/auth${endpoint}`, {
 *       method: body ? 'POST' : 'GET',
 *       headers: {
 *         'Content-Type': 'application/json',
 *         'Authorization': `Bearer ${sessionToken}`,
 *       },
 *       body: body ? JSON.stringify(body) : undefined,
 *     })
 *     if (!res.ok) throw new Error((await res.json()).error)
 *     return res.json()
 *   }
 * })
 * ```
 */
export function createClient<
  TUserMetadata extends MetadataObject = MetadataObject,
  TCredentialMetadata extends MetadataObject = MetadataObject,
>(config: ClientConfig): PasskeyMagicClient<TUserMetadata, TCredentialMetadata> {
  const request: ClientConfig['request'] = async <T = unknown>(endpoint: string, body?: unknown): Promise<T> => {
    try {
      return await config.request<T>(endpoint, body)
    } catch (error) {
      throw normalizeAuthClientError(error)
    }
  }

  const passkey = createClientPasskeyManager({ request })
  const qr = createClientQRManager({ request })
  const magicLink = createClientMagicLinkManager({ request })

  const client: PasskeyMagicClient<TUserMetadata, TCredentialMetadata> = {
    passkeys: {
      register: (params) => passkey.register(params),
      signIn: (params) => passkey.authenticate(params),
      async add(params) {
        const { options } = await request<{
          options: Parameters<typeof import('@simplewebauthn/browser').startRegistration>[0]['optionsJSON']
        }>('/passkey/add/options', params ?? {})
        const { startRegistration } = await import('@simplewebauthn/browser')
        const response = await startRegistration({ optionsJSON: options })
        return request('/passkey/add/verify', { response })
      },
      list: () => request('/account/credentials'),
      async update({ credentialId, label, metadata }) {
        await request(`/account/credentials/${credentialId}`, { label, metadata })
      },
      async remove(credentialId) {
        await request(`/account/credentials/${credentialId}/delete`, {})
      },
    },
    qr: {
      create: () => qr.createSession(),
      render: (url, opts) => qr.renderSVG(url, opts),
      renderText: (url, opts) => qr.renderText(url, opts),
      poll: (id, statusToken, opts) => qr.pollSession(id, statusToken, opts),
      waitForAuthentication: (id, statusToken, opts) => qr.waitForAuthentication(id, statusToken, opts),
      confirm: (params) => qr.confirmSession(params),
      complete: (params) => qr.completeSession(params),
      cancel: (params) => qr.cancelSession(params),
    },
    magicLinks: {
      request: (params) => magicLink.send(params),
      verify: (params) => magicLink.verify(params),
      extractToken: (input) => magicLink.extractToken(input),
      verifyURL: ({ url }) => magicLink.verifyURL(url),
    },
    accounts: {
      get: () => request('/account'),
      async isEmailAvailable(email) {
        const result = await request<{ available: boolean }>('/account/email-available', { email })
        return result.available
      },
      canLinkEmail: (email) => request('/account/can-link-email', { email }),
      updateMetadata: (metadata: User<TUserMetadata>['metadata']) => request('/account/update', { metadata }),
      linkEmail: (email) => request('/account/link-email', { email }),
      unlinkEmail: () => request('/account/unlink-email', {}),
      async delete() {
        await request('/account/delete', {})
      },
    },

    // Passkey
    supportsPasskeys: () => passkey.supportsPasskeys(),
    supportsAutofill: () => passkey.supportsAutofill(),
    hasPlatformAuthenticator: () => passkey.hasPlatformAuthenticator(),
    registerPasskey: (params) => passkey.register(params),
    signInWithPasskey: (params) => passkey.authenticate(params),

    // Passkey management
    async addPasskey(params) {
      const { options } = await request<{
        options: Parameters<typeof import('@simplewebauthn/browser').startRegistration>[0]['optionsJSON']
      }>('/passkey/add/options', params ?? {})
      const { startRegistration } = await import('@simplewebauthn/browser')
      const response = await startRegistration({ optionsJSON: options })
      return request('/passkey/add/verify', { response })
    },
    async updateCredential({ credentialId, label, metadata }) {
      await request(`/account/credentials/${credentialId}`, { label, metadata })
    },
    async removeCredential(credentialId) {
      await request(`/account/credentials/${credentialId}/delete`, {})
    },
    listCredentials: () => request('/account/credentials'),

    // QR
    createQRSession: () => qr.createSession(),
    renderQR: (url, opts) => qr.renderSVG(url, opts),
    renderQRText: (url, opts) => qr.renderText(url, opts),
    pollQRSession: (id, statusToken, opts) => qr.pollSession(id, statusToken, opts),
    waitForQRSession: (id, statusToken, opts) => qr.waitForAuthentication(id, statusToken, opts),
    confirmQRSession: (params) => qr.confirmSession(params),
    completeQRSession: (params) => qr.completeSession(params),
    cancelQRSession: (params) => qr.cancelSession(params),

    // Magic link
    requestMagicLink: (params) => magicLink.send(params),
    verifyMagicLink: (params) => magicLink.verify(params),
    extractMagicLinkToken: (input) => magicLink.extractToken(input),
    verifyMagicLinkURL: ({ url }) => magicLink.verifyURL(url),

    // Session
    async getSession() {
      try {
        return await request('/session')
      } catch {
        return null
      }
    },
    listSessions: () => request('/account/sessions'),
    async revokeSession() {
      await request('/session/revoke', {})
    },
    async revokeSessionById(sessionId) {
      await request(`/account/sessions/${sessionId}/delete`, {})
    },
    async revokeAllSessions() {
      await request('/account/sessions/delete-all', {})
    },

    // Account
    getAccount: () => request('/account'),
    async isEmailAvailable(email) {
      const result = await request<{ available: boolean }>('/account/email-available', { email })
      return result.available
    },
    updateAccountMetadata: (metadata: User<TUserMetadata>['metadata']) => request('/account/update', { metadata }),
    async linkEmail(email) {
      return request('/account/link-email', { email })
    },
    async unlinkEmail() {
      return request('/account/unlink-email', {})
    },
    async deleteAccount() {
      await request('/account/delete', {})
    },
  }

  return client
}

// Re-export types
export type { ClientConfig, QRSessionStatus } from '../types.js'
