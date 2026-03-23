import type { ClientConfig, Credential, EmailLinkability, MetadataObject, QRSessionStatus, Session, User } from '../types.js'
import { createClientPasskeyManager } from './passkey.js'
import { createClientQRManager } from './qr.js'
import { createClientMagicLinkManager } from './magic-link.js'

type ClientUser<TUserMetadata extends MetadataObject> = Pick<User<TUserMetadata>, 'id' | 'email' | 'metadata'>
type SessionObserverOptions = { intervalMs?: number; immediate?: boolean }
type SessionListener<TUserMetadata extends MetadataObject> = (session: { user: User<TUserMetadata>; session: Session } | null) => void

export interface QRClientFlow {
  sessionId: string
  statusToken: string
  confirmationCode?: string
  render(opts?: { border?: number }): string
  renderText(opts?: { border?: number }): string
  poll(opts?: { interval?: number; signal?: AbortSignal; backoffRate?: number; maxInterval?: number; jitter?: number }): AsyncIterable<QRSessionStatus>
  waitForAuthentication(opts?: { interval?: number; signal?: AbortSignal; timeoutMs?: number }): Promise<{ token: string; expiresAt: string }>
  cancel(opts?: { signal?: AbortSignal }): Promise<void>
}

export type PasskeySignInMethod = 'passkey-autofill' | 'passkey' | 'magic-link'

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
    register: (params?: { userId?: string; email?: string; userName?: string }, opts?: { signal?: AbortSignal }) => Promise<{
      method: 'passkey'
      user: ClientUser<TUserMetadata>
      session: { token: string; expiresAt: string; authMethod: 'passkey'; authContext?: { qrSessionId?: string } }
      credential: { id: string }
    }>
    signIn: (params?: { userId?: string }, opts?: { signal?: AbortSignal }) => Promise<{
      method: 'passkey'
      user: ClientUser<TUserMetadata>
      session: { token: string; expiresAt: string; authMethod: 'passkey'; authContext?: { qrSessionId?: string } }
    }>
    add: (params?: { userName?: string }, opts?: { signal?: AbortSignal }) => Promise<{ credential: { id: string } }>
    list(userId?: string, opts?: { signal?: AbortSignal }): Promise<{ credentials: Credential<TCredentialMetadata>[] }>
    update(params: { credentialId: string; label?: string; metadata?: Credential<TCredentialMetadata>['metadata'] }, opts?: { signal?: AbortSignal }): Promise<void>
    remove(credentialId: string, opts?: { signal?: AbortSignal }): Promise<void>
  }

  qr: {
    /** Create a desktop QR session and keep `statusToken` private for polling/cancellation. */
    create(): Promise<{ sessionId: string; statusToken: string; confirmationCode?: string }>
    render(url: string, opts?: { border?: number }): string
    renderText(url: string, opts?: { border?: number }): string
    /** Poll QR status with the desktop-only `statusToken`. */
    poll(sessionId: string, statusToken: string, opts?: { interval?: number; signal?: AbortSignal; backoffRate?: number; maxInterval?: number; jitter?: number }): AsyncIterable<QRSessionStatus>
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
    createFlow(params?: { urlBuilder?: (sessionId: string) => string }): Promise<QRClientFlow>
  }

  magicLinks: {
    request(params: { email: string }, opts?: { signal?: AbortSignal }): Promise<{ sent: true }>
    verify(params: { token: string }, opts?: { signal?: AbortSignal }): Promise<{
      method: 'magic-link'
      user: ClientUser<TUserMetadata>
      session: { token: string; expiresAt: string; authMethod: 'magic-link'; authContext?: { qrSessionId?: string } }
      isNewUser: boolean
    }>
    extractToken(input: string | URL): string
    verifyURL(params: { url: string | URL }, opts?: { signal?: AbortSignal }): Promise<{
      method: 'magic-link'
      user: ClientUser<TUserMetadata>
      session: { token: string; expiresAt: string; authMethod: 'magic-link'; authContext?: { qrSessionId?: string } }
      isNewUser: boolean
    }>
  }

  accounts: {
    get(opts?: { signal?: AbortSignal }): Promise<{ user: User<TUserMetadata> }>
    isEmailAvailable(email: string, opts?: { signal?: AbortSignal }): Promise<boolean>
    canLinkEmail(email: string, opts?: { signal?: AbortSignal }): Promise<EmailLinkability>
    updateMetadata(metadata?: User<TUserMetadata>['metadata'], opts?: { signal?: AbortSignal }): Promise<{ user: User<TUserMetadata> }>
    linkEmail(email: string, opts?: { signal?: AbortSignal }): Promise<{ user: User<TUserMetadata> }>
    unlinkEmail(opts?: { signal?: AbortSignal }): Promise<{ user: User<TUserMetadata> }>
    delete(opts?: { signal?: AbortSignal }): Promise<void>
  }

  // ── Passkey ──

  /** Check if the browser supports WebAuthn. */
  supportsPasskeys(): boolean
  /** Check if the browser supports WebAuthn conditional UI (autofill). */
  supportsAutofill(): Promise<boolean>
  /** Check if a platform authenticator (Touch ID, Windows Hello) is available. */
  hasPlatformAuthenticator(): Promise<boolean>
  /** Infer the best sign-in method for the current browser. */
  getBestSignInMethod(opts?: { allowMagicLink?: boolean }): Promise<PasskeySignInMethod>

  /** Register a new passkey and create an account. */
  registerPasskey(params?: {
    userId?: string
    email?: string
    userName?: string
  }, opts?: { signal?: AbortSignal }): Promise<{
    method: 'passkey'
    user: ClientUser<TUserMetadata>
    session: { token: string; expiresAt: string; authMethod: 'passkey'; authContext?: { qrSessionId?: string } }
    credential: { id: string }
  }>

  /** Sign in with an existing passkey. */
  signInWithPasskey(params?: {
    userId?: string
  }, opts?: { signal?: AbortSignal }): Promise<{
    method: 'passkey'
    user: ClientUser<TUserMetadata>
    session: { token: string; expiresAt: string; authMethod: 'passkey'; authContext?: { qrSessionId?: string } }
  }>

  // ── Passkey Management ──

  /** Add a passkey to the current account (requires auth). */
  addPasskey(params?: { userName?: string }, opts?: { signal?: AbortSignal }): Promise<{ credential: { id: string } }>
  /** Update a passkey label. */
  updateCredential(params: { credentialId: string; label?: string; metadata?: Credential<TCredentialMetadata>['metadata'] }, opts?: { signal?: AbortSignal }): Promise<void>
  /** Remove a passkey. */
  removeCredential(credentialId: string, opts?: { signal?: AbortSignal }): Promise<void>
  /** List all passkeys for the current user. */
  listCredentials(opts?: { signal?: AbortSignal }): Promise<{ credentials: Credential<TCredentialMetadata>[] }>

  // ── QR Cross-Device ──

  /** Create a new QR login session on the server. Keep `statusToken` private on the desktop. */
  createQRSession(opts?: { signal?: AbortSignal }): Promise<{ sessionId: string; statusToken: string; confirmationCode?: string }>
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
    opts?: { interval?: number; signal?: AbortSignal; backoffRate?: number; maxInterval?: number; jitter?: number },
  ): AsyncIterable<QRSessionStatus>
  /** Wait for QR authentication to succeed or fail terminally. */
  waitForQRSession(
    sessionId: string,
    statusToken: string,
    opts?: { interval?: number; signal?: AbortSignal; timeoutMs?: number },
  ): Promise<{ token: string; expiresAt: string }>
  /** Complete a QR session from the scanning device (authenticates with passkey). */
  confirmQRSession(params: { sessionId: string; confirmationCode: string }, opts?: { signal?: AbortSignal }): Promise<void>
  completeQRSession(params: { sessionId: string; confirmationCode?: string }, opts?: { signal?: AbortSignal }): Promise<void>
  /** Cancel a QR session before it completes. */
  cancelQRSession(params: { sessionId: string; statusToken: string }, opts?: { signal?: AbortSignal }): Promise<void>

  // ── Magic Link ──

  /** Request a magic link email. */
  requestMagicLink(params: { email: string }, opts?: { signal?: AbortSignal }): Promise<{ sent: true }>
  /** Verify a magic link token and create a session. */
  verifyMagicLink(params: { token: string }, opts?: { signal?: AbortSignal }): Promise<{
    method: 'magic-link'
    user: ClientUser<TUserMetadata>
    session: { token: string; expiresAt: string; authMethod: 'magic-link'; authContext?: { qrSessionId?: string } }
    isNewUser: boolean
  }>
  /** Extract a magic-link token from a callback URL. */
  extractMagicLinkToken(input: string | URL): string
  /** Verify a magic-link token directly from a callback URL. */
  verifyMagicLinkURL(params: { url: string | URL }, opts?: { signal?: AbortSignal }): Promise<{
    method: 'magic-link'
    user: ClientUser<TUserMetadata>
    session: { token: string; expiresAt: string; authMethod: 'magic-link'; authContext?: { qrSessionId?: string } }
    isNewUser: boolean
  }>

  // ── Session Management ──

  /** Validate the current session. Returns null if invalid/expired. */
  getSession(opts?: { signal?: AbortSignal }): Promise<{ user: User<TUserMetadata>; session: Session } | null>
  /** Observe session changes by polling `getSession()`. Returns an unsubscribe function. */
  observeSession(listener: SessionListener<TUserMetadata>, opts?: SessionObserverOptions): () => void
  /** List all active sessions. */
  listSessions(opts?: { signal?: AbortSignal }): Promise<{ sessions: Session[] }>
  /** Revoke the current session (logout). */
  revokeSession(opts?: { signal?: AbortSignal }): Promise<void>
  /** Revoke a specific session by ID. */
  revokeSessionById(sessionId: string, opts?: { signal?: AbortSignal }): Promise<void>
  /** Revoke all sessions (logout everywhere). */
  revokeAllSessions(opts?: { signal?: AbortSignal }): Promise<void>

  // ── Account Management ──

  /** Get the current user profile. */
  getAccount(opts?: { signal?: AbortSignal }): Promise<{ user: User<TUserMetadata> }>
  /** Check if an email is available. */
  isEmailAvailable(email: string, opts?: { signal?: AbortSignal }): Promise<boolean>
  /** Update metadata on the current account. */
  updateAccountMetadata(metadata?: User<TUserMetadata>['metadata'], opts?: { signal?: AbortSignal }): Promise<{ user: User<TUserMetadata> }>
  /** Link an email to the current account. */
  linkEmail(email: string, opts?: { signal?: AbortSignal }): Promise<{ user: User<TUserMetadata> }>
  /** Unlink the email from the current account. */
  unlinkEmail(opts?: { signal?: AbortSignal }): Promise<{ user: User<TUserMetadata> }>
  /** Delete the current account and all data. */
  deleteAccount(opts?: { signal?: AbortSignal }): Promise<void>
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
  const request: ClientConfig['request'] = async <T = unknown>(endpoint: string, body?: unknown, options?: { signal?: AbortSignal }): Promise<T> => {
    try {
      return await config.request<T>(endpoint, body, options)
    } catch (error) {
      throw normalizeAuthClientError(error)
    }
  }

  const passkey = createClientPasskeyManager({ request })
  const qr = createClientQRManager({ request })
  const magicLink = createClientMagicLinkManager({ request })

  function createQRFlow(sessionId: string, statusToken: string, confirmationCode?: string, urlBuilder?: (sessionId: string) => string): QRClientFlow {
    const builder = urlBuilder ?? ((id: string) => id)
    return {
      sessionId,
      statusToken,
      confirmationCode,
      render: (opts) => qr.renderSVG(builder(sessionId), opts),
      renderText: (opts) => qr.renderText(builder(sessionId), opts),
      poll: (opts) => qr.pollSession(sessionId, statusToken, opts),
      waitForAuthentication: (opts) => qr.waitForAuthentication(sessionId, statusToken, opts),
      cancel: (opts) => qr.cancelSession({ sessionId, statusToken }, opts),
    }
  }

  const client: PasskeyMagicClient<TUserMetadata, TCredentialMetadata> = {
    passkeys: {
      register: (params, opts) => passkey.register(params, opts),
      signIn: (params, opts) => passkey.authenticate(params, opts),
      async add(params, opts) {
        const { options } = await request<{
          options: Parameters<typeof import('@simplewebauthn/browser').startRegistration>[0]['optionsJSON']
        }>('/passkey/add/options', params ?? {}, opts)
        const { startRegistration } = await import('@simplewebauthn/browser')
        const response = await startRegistration({ optionsJSON: options })
        return request('/passkey/add/verify', { response }, opts)
      },
      list: (_userId, opts) => request('/account/credentials', undefined, opts),
      async update({ credentialId, label, metadata }, opts) {
        await request(`/account/credentials/${credentialId}`, { label, metadata }, opts)
      },
      async remove(credentialId, opts) {
        await request(`/account/credentials/${credentialId}/delete`, {}, opts)
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
      async createFlow(params) {
        const created = await qr.createSession()
        return createQRFlow(created.sessionId, created.statusToken, created.confirmationCode, params?.urlBuilder)
      },
    },
    magicLinks: {
      request: (params, opts) => magicLink.send(params, opts),
      verify: (params, opts) => magicLink.verify(params, opts),
      extractToken: (input) => magicLink.extractToken(input),
      verifyURL: ({ url }, opts) => magicLink.verifyURL(url, opts),
    },
    accounts: {
      get: (opts) => request('/account', undefined, opts),
      async isEmailAvailable(email, opts) {
        const result = await request<{ available: boolean }>('/account/email-available', { email }, opts)
        return result.available
      },
      canLinkEmail: (email, opts) => request('/account/can-link-email', { email }, opts),
      updateMetadata: (metadata: User<TUserMetadata>['metadata'], opts) => request('/account/update', { metadata }, opts),
      linkEmail: (email, opts) => request('/account/link-email', { email }, opts),
      unlinkEmail: (opts) => request('/account/unlink-email', {}, opts),
      async delete(opts) {
        await request('/account/delete', {}, opts)
      },
    },

    // Passkey
    supportsPasskeys: () => passkey.supportsPasskeys(),
    supportsAutofill: () => passkey.supportsAutofill(),
    hasPlatformAuthenticator: () => passkey.hasPlatformAuthenticator(),
    async getBestSignInMethod(opts) {
      if (!passkey.supportsPasskeys()) {
        return opts?.allowMagicLink === false ? 'passkey' : 'magic-link'
      }
      if (await passkey.supportsAutofill()) return 'passkey-autofill'
      return 'passkey'
    },
    registerPasskey: (params, opts) => passkey.register(params, opts),
    signInWithPasskey: (params, opts) => passkey.authenticate(params, opts),

    // Passkey management
    async addPasskey(params, opts) {
      const { options } = await request<{
          options: Parameters<typeof import('@simplewebauthn/browser').startRegistration>[0]['optionsJSON']
      }>('/passkey/add/options', params ?? {}, opts)
      const { startRegistration } = await import('@simplewebauthn/browser')
      const response = await startRegistration({ optionsJSON: options })
      return request('/passkey/add/verify', { response }, opts)
    },
    async updateCredential({ credentialId, label, metadata }, opts) {
      await request(`/account/credentials/${credentialId}`, { label, metadata }, opts)
    },
    async removeCredential(credentialId, opts) {
      await request(`/account/credentials/${credentialId}/delete`, {}, opts)
    },
    listCredentials: (opts) => request('/account/credentials', undefined, opts),

    // QR
    createQRSession: () => qr.createSession(),
    renderQR: (url, opts) => qr.renderSVG(url, opts),
    renderQRText: (url, opts) => qr.renderText(url, opts),
    pollQRSession: (id, statusToken, opts) => qr.pollSession(id, statusToken, opts),
    waitForQRSession: (id, statusToken, opts) => qr.waitForAuthentication(id, statusToken, opts),
    confirmQRSession: (params, opts) => qr.confirmSession(params, opts),
    completeQRSession: (params, opts) => qr.completeSession(params, opts),
    cancelQRSession: (params, opts) => qr.cancelSession(params, opts),

    // Magic link
    requestMagicLink: (params, opts) => magicLink.send(params, opts),
    verifyMagicLink: (params, opts) => magicLink.verify(params, opts),
    extractMagicLinkToken: (input) => magicLink.extractToken(input),
    verifyMagicLinkURL: ({ url }, opts) => magicLink.verifyURL(url, opts),

    // Session
    async getSession(opts) {
      try {
        return await request('/session', undefined, opts)
      } catch {
        return null
      }
    },
    observeSession(listener, opts) {
      const intervalMs = opts?.intervalMs ?? 30_000
      let timer: ReturnType<typeof setTimeout> | null = null
      let active = true

      const tick = async () => {
        if (!active) return
        listener(await client.getSession())
        if (!active) return
        timer = setTimeout(tick, intervalMs)
      }

      if (opts?.immediate !== false) {
        void tick()
      } else {
        timer = setTimeout(tick, intervalMs)
      }

      return () => {
        active = false
        if (timer) clearTimeout(timer)
      }
    },
    listSessions: (opts) => request('/account/sessions', undefined, opts),
    async revokeSession(opts) {
      await request('/session/revoke', {}, opts)
    },
    async revokeSessionById(sessionId, opts) {
      await request(`/account/sessions/${sessionId}/delete`, {}, opts)
    },
    async revokeAllSessions(opts) {
      await request('/account/sessions/delete-all', {}, opts)
    },

    // Account
    getAccount: (opts) => request('/account', undefined, opts),
    async isEmailAvailable(email, opts) {
      const result = await request<{ available: boolean }>('/account/email-available', { email }, opts)
      return result.available
    },
    updateAccountMetadata: (metadata: User<TUserMetadata>['metadata'], opts) => request('/account/update', { metadata }, opts),
    async linkEmail(email, opts) {
      return request('/account/link-email', { email }, opts)
    },
    async unlinkEmail(opts) {
      return request('/account/unlink-email', {}, opts)
    },
    async deleteAccount(opts) {
      await request('/account/delete', {}, opts)
    },
  }

  return client
}

// Re-export types
export type { ClientConfig, QRSessionStatus } from '../types.js'
