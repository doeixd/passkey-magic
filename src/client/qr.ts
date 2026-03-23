import { renderSVG, renderUnicodeCompact } from 'uqr'
import type {
  PublicKeyCredentialRequestOptionsJSON,
} from '@simplewebauthn/browser'
import type { ClientConfig, QRSessionStatus } from '../types.js'

/** Client-side QR cross-device login manager. */
export interface ClientQRManager {
  createSession(): Promise<{ sessionId: string }>
  renderSVG(url: string, opts?: { border?: number }): string
  renderText(url: string, opts?: { border?: number }): string
  pollSession(
    sessionId: string,
    opts?: { interval?: number; signal?: AbortSignal },
  ): AsyncIterable<QRSessionStatus>
  completeSession(params: { sessionId: string }): Promise<void>
  cancelSession(sessionId: string): Promise<void>
}

export function createClientQRManager(config: ClientConfig): ClientQRManager {
  return {
    async createSession() {
      return config.request<{ sessionId: string }>('/qr/create', {})
    },

    renderSVG(url, opts) {
      return renderSVG(url, { border: opts?.border ?? 2 })
    },

    renderText(url, opts) {
      return renderUnicodeCompact(url, { border: opts?.border ?? 1 })
    },

    async *pollSession(sessionId, opts) {
      const interval = opts?.interval ?? 2000
      const signal = opts?.signal

      while (!signal?.aborted) {
        const status = await config.request<QRSessionStatus>(`/qr/${sessionId}/status`)
        yield status

        if (
          status.state === 'authenticated' ||
          status.state === 'expired' ||
          status.state === 'cancelled'
        ) {
          return
        }

        await new Promise<void>((resolve, reject) => {
          const timer = setTimeout(resolve, interval)
          signal?.addEventListener('abort', () => {
            clearTimeout(timer)
            reject(signal.reason)
          }, { once: true })
        })
      }
    },

    async completeSession({ sessionId }) {
      await config.request(`/qr/${sessionId}/scanned`, {})

      const { startAuthentication } = await import('@simplewebauthn/browser')
      const { options } = await config.request<{
        options: PublicKeyCredentialRequestOptionsJSON
      }>('/passkey/authenticate/options', {})
      const response = await startAuthentication({ optionsJSON: options })

      await config.request(`/qr/${sessionId}/complete`, { response })
    },

    async cancelSession(sessionId) {
      await config.request(`/qr/${sessionId}/cancel`, {})
    },
  }
}
