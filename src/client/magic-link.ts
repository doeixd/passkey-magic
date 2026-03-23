import type { ClientConfig } from '../types.js'

/** Client-side magic link manager. */
export interface ClientMagicLinkManager {
  send(params: { email: string }, opts?: { signal?: AbortSignal }): Promise<{ sent: true }>
  verify(params: { token: string }, opts?: { signal?: AbortSignal }): Promise<{
    method: 'magic-link'
    user: { id: string; email?: string }
    session: { token: string; expiresAt: string; authMethod: 'magic-link'; authContext?: { qrSessionId?: string } }
    isNewUser: boolean
  }>
  extractToken(input: string | URL): string
  verifyURL(input: string | URL, opts?: { signal?: AbortSignal }): Promise<{
    method: 'magic-link'
    user: { id: string; email?: string }
    session: { token: string; expiresAt: string; authMethod: 'magic-link'; authContext?: { qrSessionId?: string } }
    isNewUser: boolean
  }>
}

export function createClientMagicLinkManager(config: ClientConfig): ClientMagicLinkManager {
  return {
    async send({ email }, opts) {
      return config.request('/magic-link/send', { email }, opts)
    },

    async verify({ token }, opts) {
      return config.request('/magic-link/verify', { token }, opts)
    },

    extractToken(input) {
      const url = typeof input === 'string' ? new URL(input, 'http://localhost') : input
      const token = url.searchParams.get('token')
      if (!token) {
        throw new Error('Magic link token missing from URL')
      }
      return token
    },

    async verifyURL(input, opts) {
      const token = this.extractToken(input)
      return this.verify({ token }, opts)
    },
  }
}
