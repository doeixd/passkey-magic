import type { ClientConfig } from '../types.js'

/** Client-side magic link manager. */
export interface ClientMagicLinkManager {
  send(params: { email: string }): Promise<{ sent: true }>
  verify(params: { token: string }): Promise<{
    method: 'magic-link'
    user: { id: string; email?: string }
    session: { token: string; expiresAt: string }
    isNewUser: boolean
  }>
}

export function createClientMagicLinkManager(config: ClientConfig): ClientMagicLinkManager {
  return {
    async send({ email }) {
      return config.request('/magic-link/send', { email })
    },

    async verify({ token }) {
      return config.request('/magic-link/verify', { token })
    },
  }
}
