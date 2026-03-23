import { renderSVG, renderUnicodeCompact } from 'uqr'
import type {
  PublicKeyCredentialRequestOptionsJSON,
} from '@simplewebauthn/browser'
import type { ClientConfig, QRSessionStatus } from '../types.js'

/** Client-side QR cross-device login manager. */
export interface ClientQRManager {
  createSession(): Promise<{ sessionId: string; statusToken: string; confirmationCode?: string }>
  renderSVG(url: string, opts?: { border?: number }): string
  renderText(url: string, opts?: { border?: number }): string
  pollSession(
    sessionId: string,
    statusToken: string,
    opts?: { interval?: number; signal?: AbortSignal; backoffRate?: number; maxInterval?: number; jitter?: number },
  ): AsyncIterable<QRSessionStatus>
  waitForAuthentication(
    sessionId: string,
    statusToken: string,
    opts?: { interval?: number; signal?: AbortSignal; timeoutMs?: number },
  ): Promise<{ token: string; expiresAt: string }>
  confirmSession(params: { sessionId: string; confirmationCode: string }, opts?: { signal?: AbortSignal }): Promise<void>
  completeSession(params: { sessionId: string; confirmationCode?: string }, opts?: { signal?: AbortSignal }): Promise<void>
  cancelSession(params: { sessionId: string; statusToken: string }, opts?: { signal?: AbortSignal }): Promise<void>
}

export function createClientQRManager(config: ClientConfig): ClientQRManager {
  return {
    async createSession() {
      return config.request<{ sessionId: string; statusToken: string; confirmationCode?: string }>('/qr/create', {}, undefined)
    },

    renderSVG(url, opts) {
      return renderSVG(url, { border: opts?.border ?? 2 })
    },

    renderText(url, opts) {
      return renderUnicodeCompact(url, { border: opts?.border ?? 1 })
    },

    async *pollSession(sessionId, statusToken, opts) {
      const baseInterval = opts?.interval ?? 2000
      const backoffRate = Math.max(1, opts?.backoffRate ?? 1)
      const maxInterval = Math.max(baseInterval, opts?.maxInterval ?? baseInterval)
      const jitter = Math.max(0, Math.min(1, opts?.jitter ?? 0))
      const signal = opts?.signal
      let attempt = 0

      while (!signal?.aborted) {
        const status = await config.request<QRSessionStatus>(`/qr/${sessionId}/status?token=${encodeURIComponent(statusToken)}`, undefined, { signal })
        yield status

        if (
          status.state === 'authenticated' ||
          status.state === 'expired' ||
          status.state === 'cancelled'
        ) {
          return
        }

        const nextInterval = Math.min(maxInterval, Math.round(baseInterval * Math.pow(backoffRate, attempt)))
        const randomizedInterval = jitter > 0
          ? Math.max(0, Math.round(nextInterval * (1 - jitter + Math.random() * jitter * 2)))
          : nextInterval
        attempt += 1

        await new Promise<void>((resolve, reject) => {
          const timer = setTimeout(resolve, randomizedInterval)
          signal?.addEventListener('abort', () => {
            clearTimeout(timer)
            reject(signal.reason)
          }, { once: true })
        })
      }
    },

    async waitForAuthentication(sessionId, statusToken, opts) {
      const startedAt = Date.now()
      for await (const status of this.pollSession(sessionId, statusToken, opts)) {
        if (status.state === 'authenticated' && status.session) {
          return status.session
        }
        if (status.state === 'expired') {
          throw new Error('QR session expired')
        }
        if (status.state === 'cancelled') {
          throw new Error('QR session cancelled')
        }
        if (opts?.timeoutMs && Date.now() - startedAt >= opts.timeoutMs) {
          throw new Error('QR session timed out')
        }
      }
      throw new Error('QR session stopped before authentication')
    },

    async confirmSession({ sessionId, confirmationCode }, opts) {
      await config.request(`/qr/${sessionId}/confirm`, { confirmationCode }, opts)
    },

    async completeSession({ sessionId, confirmationCode }, opts) {
      await config.request(`/qr/${sessionId}/scanned`, {}, opts)

      if (confirmationCode) {
        await config.request(`/qr/${sessionId}/confirm`, { confirmationCode }, opts)
      }

      const { startAuthentication } = await import('@simplewebauthn/browser')
      const { options } = await config.request<{
        options: PublicKeyCredentialRequestOptionsJSON
      }>('/passkey/authenticate/options', {}, opts)
      const response = await startAuthentication({ optionsJSON: options })

      await config.request(`/qr/${sessionId}/complete`, { response }, opts)
    },

    async cancelSession({ sessionId, statusToken }, opts) {
      await config.request(`/qr/${sessionId}/cancel`, { statusToken }, opts)
    },
  }
}
