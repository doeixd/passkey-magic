import type { ClientConfig, Credential, EmailLinkability, QRSessionStatus, Session, User } from '../types.js'
import { createClientPasskeyManager } from './passkey.js'
import { createClientQRManager } from './qr.js'
import { createClientMagicLinkManager } from './magic-link.js'

/**
 * Client-side auth interface. All methods delegate to the server
 * via the `request` function you provide in config.
 */
export interface PasskeyMagicClient {
  passkeys: {
    register: (params?: { userId?: string; email?: string; userName?: string }) => Promise<{
      method: 'passkey'
      user: { id: string; email?: string }
      session: { token: string; expiresAt: string; authMethod: 'passkey'; authContext?: { qrSessionId?: string } }
      credential: { id: string }
    }>
    signIn: (params?: { userId?: string }) => Promise<{
      method: 'passkey'
      user: { id: string; email?: string }
      session: { token: string; expiresAt: string; authMethod: 'passkey'; authContext?: { qrSessionId?: string } }
    }>
    add: (params?: { userName?: string }) => Promise<{ credential: { id: string } }>
    list(userId?: string): Promise<{ credentials: Credential[] }>
    update(params: { credentialId: string; label: string }): Promise<void>
    remove(credentialId: string): Promise<void>
  }

  qr: {
    create(): Promise<{ sessionId: string }>
    render(url: string, opts?: { border?: number }): string
    renderText(url: string, opts?: { border?: number }): string
    poll(sessionId: string, opts?: { interval?: number; signal?: AbortSignal }): AsyncIterable<QRSessionStatus>
    complete(params: { sessionId: string }): Promise<void>
    cancel(sessionId: string): Promise<void>
  }

  magicLinks: {
    request(params: { email: string }): Promise<{ sent: true }>
    verify(params: { token: string }): Promise<{
      method: 'magic-link'
      user: { id: string; email?: string }
      session: { token: string; expiresAt: string; authMethod: 'magic-link'; authContext?: { qrSessionId?: string } }
      isNewUser: boolean
    }>
  }

  accounts: {
    get(): Promise<{ user: User }>
    isEmailAvailable(email: string): Promise<boolean>
    canLinkEmail(email: string): Promise<EmailLinkability>
    linkEmail(email: string): Promise<{ user: User }>
    unlinkEmail(): Promise<{ user: User }>
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
    user: { id: string; email?: string }
    session: { token: string; expiresAt: string; authMethod: 'passkey'; authContext?: { qrSessionId?: string } }
    credential: { id: string }
  }>

  /** Sign in with an existing passkey. */
  signInWithPasskey(params?: {
    userId?: string
  }): Promise<{
    method: 'passkey'
    user: { id: string; email?: string }
    session: { token: string; expiresAt: string; authMethod: 'passkey'; authContext?: { qrSessionId?: string } }
  }>

  // ── Passkey Management ──

  /** Add a passkey to the current account (requires auth). */
  addPasskey(params?: { userName?: string }): Promise<{ credential: { id: string } }>
  /** Update a passkey label. */
  updateCredential(params: { credentialId: string; label: string }): Promise<void>
  /** Remove a passkey. */
  removeCredential(credentialId: string): Promise<void>
  /** List all passkeys for the current user. */
  listCredentials(): Promise<{ credentials: Credential[] }>

  // ── QR Cross-Device ──

  /** Create a new QR login session on the server. */
  createQRSession(): Promise<{ sessionId: string }>
  /** Render a URL as an SVG QR code using uqr. */
  renderQR(url: string, opts?: { border?: number }): string
  /** Render a URL as a text QR code using uqr. */
  renderQRText(url: string, opts?: { border?: number }): string
  /**
   * Poll a QR session for status changes.
   * Yields status updates until `authenticated` or `expired`.
   */
  pollQRSession(
    sessionId: string,
    opts?: { interval?: number; signal?: AbortSignal },
  ): AsyncIterable<QRSessionStatus>
  /** Complete a QR session from the scanning device (authenticates with passkey). */
  completeQRSession(params: { sessionId: string }): Promise<void>
  /** Cancel a QR session before it completes. */
  cancelQRSession(sessionId: string): Promise<void>

  // ── Magic Link ──

  /** Request a magic link email. */
  requestMagicLink(params: { email: string }): Promise<{ sent: true }>
  /** Verify a magic link token and create a session. */
  verifyMagicLink(params: { token: string }): Promise<{
    method: 'magic-link'
    user: { id: string; email?: string }
    session: { token: string; expiresAt: string; authMethod: 'magic-link'; authContext?: { qrSessionId?: string } }
    isNewUser: boolean
  }>

  // ── Session Management ──

  /** Validate the current session. Returns null if invalid/expired. */
  getSession(): Promise<{ user: User; session: Session } | null>
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
  getAccount(): Promise<{ user: User }>
  /** Check if an email is available. */
  isEmailAvailable(email: string): Promise<boolean>
  /** Link an email to the current account. */
  linkEmail(email: string): Promise<{ user: User }>
  /** Unlink the email from the current account. */
  unlinkEmail(): Promise<{ user: User }>
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
export function createClient(config: ClientConfig): PasskeyMagicClient {
  const passkey = createClientPasskeyManager(config)
  const qr = createClientQRManager(config)
  const magicLink = createClientMagicLinkManager(config)

  const client: PasskeyMagicClient = {
    passkeys: {
      register: (params) => passkey.register(params),
      signIn: (params) => passkey.authenticate(params),
      async add(params) {
        const { options } = await config.request<{
          options: Parameters<typeof import('@simplewebauthn/browser').startRegistration>[0]['optionsJSON']
        }>('/passkey/add/options', params ?? {})
        const { startRegistration } = await import('@simplewebauthn/browser')
        const response = await startRegistration({ optionsJSON: options })
        return config.request('/passkey/add/verify', { response })
      },
      list: () => config.request('/account/credentials'),
      async update({ credentialId, label }) {
        await config.request(`/account/credentials/${credentialId}`, { label })
      },
      async remove(credentialId) {
        await config.request(`/account/credentials/${credentialId}/delete`, {})
      },
    },
    qr: {
      create: () => qr.createSession(),
      render: (url, opts) => qr.renderSVG(url, opts),
      renderText: (url, opts) => qr.renderText(url, opts),
      poll: (id, opts) => qr.pollSession(id, opts),
      complete: (params) => qr.completeSession(params),
      cancel: (sessionId) => qr.cancelSession(sessionId),
    },
    magicLinks: {
      request: (params) => magicLink.send(params),
      verify: (params) => magicLink.verify(params),
    },
    accounts: {
      get: () => config.request('/account'),
      async isEmailAvailable(email) {
        const result = await config.request<{ available: boolean }>('/account/email-available', { email })
        return result.available
      },
      canLinkEmail: (email) => config.request('/account/can-link-email', { email }),
      linkEmail: (email) => config.request('/account/link-email', { email }),
      unlinkEmail: () => config.request('/account/unlink-email', {}),
      async delete() {
        await config.request('/account/delete', {})
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
      const { options } = await config.request<{
        options: Parameters<typeof import('@simplewebauthn/browser').startRegistration>[0]['optionsJSON']
      }>('/passkey/add/options', params ?? {})
      const { startRegistration } = await import('@simplewebauthn/browser')
      const response = await startRegistration({ optionsJSON: options })
      return config.request('/passkey/add/verify', { response })
    },
    async updateCredential({ credentialId, label }) {
      await config.request(`/account/credentials/${credentialId}`, { label })
    },
    async removeCredential(credentialId) {
      await config.request(`/account/credentials/${credentialId}/delete`, {})
    },
    listCredentials: () => config.request('/account/credentials'),

    // QR
    createQRSession: () => qr.createSession(),
    renderQR: (url, opts) => qr.renderSVG(url, opts),
    renderQRText: (url, opts) => qr.renderText(url, opts),
    pollQRSession: (id, opts) => qr.pollSession(id, opts),
    completeQRSession: (params) => qr.completeSession(params),
    cancelQRSession: (sessionId) => qr.cancelSession(sessionId),

    // Magic link
    requestMagicLink: (params) => magicLink.send(params),
    verifyMagicLink: (params) => magicLink.verify(params),

    // Session
    async getSession() {
      try {
        return await config.request('/session')
      } catch {
        return null
      }
    },
    listSessions: () => config.request('/account/sessions'),
    async revokeSession() {
      await config.request('/session/revoke', {})
    },
    async revokeSessionById(sessionId) {
      await config.request(`/account/sessions/${sessionId}/delete`, {})
    },
    async revokeAllSessions() {
      await config.request('/account/sessions/delete-all', {})
    },

    // Account
    getAccount: () => config.request('/account'),
    async isEmailAvailable(email) {
      const result = await config.request<{ available: boolean }>('/account/email-available', { email })
      return result.available
    },
    async linkEmail(email) {
      return config.request('/account/link-email', { email })
    },
    async unlinkEmail() {
      return config.request('/account/unlink-email', {})
    },
    async deleteAccount() {
      await config.request('/account/delete', {})
    },
  }

  return client
}

// Re-export types
export type { ClientConfig, QRSessionStatus } from '../types.js'
