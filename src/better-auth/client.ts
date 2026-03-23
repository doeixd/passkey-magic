import type {
  BetterAuthClientPlugin,
} from 'better-auth/client'
import type { passkeyMagicPlugin } from './index.js'
import type {
  AuthenticationResponseJSON,
  RegistrationResponseJSON,
} from '@simplewebauthn/server'
import type { Credential, User } from '../types.js'

interface BetterAuthFetch {
  <T = unknown>(path: string, options?: {
    method?: string
    body?: unknown
    query?: Record<string, unknown>
  }): Promise<T>
}

export const passkeyMagicClientPlugin = () =>
  ({
    id: 'passkey-magic',
    $InferServerPlugin: {} as ReturnType<typeof passkeyMagicPlugin>,
    getActions: ($fetch: BetterAuthFetch) => ({
      passkeyMagic: {
        register: {
          options: (body?: { userId?: string; email?: string; userName?: string }) =>
            $fetch('/passkey-magic/register/options', { method: 'POST', body }),
          verify: (body: { userId: string; response: RegistrationResponseJSON }) =>
            $fetch('/passkey-magic/register/verify', { method: 'POST', body }),
        },
        authenticate: {
          options: (body?: { userId?: string }) =>
            $fetch('/passkey-magic/authenticate/options', { method: 'POST', body }),
          verify: (body: { response: AuthenticationResponseJSON }) =>
            $fetch('/passkey-magic/authenticate/verify', { method: 'POST', body }),
        },
        passkeys: {
          add: {
            options: (body?: { userName?: string }) =>
              $fetch('/passkey-magic/add/options', { method: 'POST', body }),
            verify: (body: { response: RegistrationResponseJSON }) =>
              $fetch('/passkey-magic/add/verify', { method: 'POST', body }),
          },
          list: () =>
            $fetch('/passkey-magic/credentials', { method: 'GET' }),
          update: (body: { credentialId: string; label?: string; metadata?: Credential['metadata'] }) =>
            $fetch('/passkey-magic/credentials/update', { method: 'POST', body }),
          remove: (body: { credentialId: string }) =>
            $fetch('/passkey-magic/credentials/remove', { method: 'POST', body }),
        },
        qr: {
          create: () =>
            $fetch('/passkey-magic/qr/create', { method: 'POST' }),
          status: (sessionId: string) =>
            $fetch('/passkey-magic/qr/status', { method: 'GET', query: { sessionId } }),
          scanned: (body: { sessionId: string }) =>
            $fetch('/passkey-magic/qr/scanned', { method: 'POST', body }),
          complete: (body: { sessionId: string; response: AuthenticationResponseJSON }) =>
            $fetch('/passkey-magic/qr/complete', { method: 'POST', body }),
        },
        magicLinks: {
          send: (body: { email: string }) =>
            $fetch('/passkey-magic/magic-link/send', { method: 'POST', body }),
          verify: (body: { token: string }) =>
            $fetch('/passkey-magic/magic-link/verify', { method: 'POST', body }),
        },
        accounts: {
          canLinkEmail: (body: { email: string }) =>
            $fetch('/passkey-magic/account/can-link-email', { method: 'POST', body }),
          updateMetadata: (body: { metadata?: User['metadata'] }) =>
            $fetch('/passkey-magic/account/update', { method: 'POST', body }),
        },
      },
    }),
    pathMethods: {
      '/passkey-magic/qr/status': 'GET',
    },
  }) satisfies BetterAuthClientPlugin
