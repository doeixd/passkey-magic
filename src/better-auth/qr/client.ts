import type { BetterAuthClientPlugin } from 'better-auth/client'
import type { passkeyMagicQRPlugin } from './index.js'

interface BetterAuthFetch {
  <T = unknown>(path: string, options?: {
    method?: string
    body?: unknown
    query?: Record<string, unknown>
  }): Promise<T>
}

/** Focused Better Auth client plugin exposing only QR cross-device helpers. */
export const passkeyMagicQRClientPlugin = () =>
  ({
    id: 'passkey-magic-qr',
    $InferServerPlugin: {} as ReturnType<typeof passkeyMagicQRPlugin>,
    getActions: ($fetch: BetterAuthFetch) => ({
      passkeyMagicQr: {
        create: () =>
          $fetch('/passkey-magic/qr/create', { method: 'POST' }),
        status: (sessionId: string, statusToken: string) =>
          $fetch('/passkey-magic/qr/status', { method: 'GET', query: { sessionId, statusToken } }),
        scanned: (body: { sessionId: string }) =>
          $fetch('/passkey-magic/qr/scanned', { method: 'POST', body }),
        confirm: (body: { sessionId: string; confirmationCode: string }) =>
          $fetch('/passkey-magic/qr/confirm', { method: 'POST', body }),
        complete: (body: { sessionId: string; response: unknown }) =>
          $fetch('/passkey-magic/qr/complete', { method: 'POST', body }),
      },
    }),
    pathMethods: {
      '/passkey-magic/qr/status': 'GET',
    },
  }) satisfies BetterAuthClientPlugin
