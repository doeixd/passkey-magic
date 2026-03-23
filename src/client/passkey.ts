import {
  browserSupportsWebAuthn,
  browserSupportsWebAuthnAutofill,
  platformAuthenticatorIsAvailable,
  startAuthentication,
  startRegistration,
} from '@simplewebauthn/browser'
import type {
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
} from '@simplewebauthn/browser'
import type { ClientConfig } from '../types.js'

export interface ClientPasskeyManager {
  supportsPasskeys(): boolean
  supportsAutofill(): Promise<boolean>
  hasPlatformAuthenticator(): Promise<boolean>

  register(params?: {
    userId?: string
    email?: string
    userName?: string
  }): Promise<{
    method: 'passkey'
    user: { id: string; email?: string }
    session: { token: string; expiresAt: string; authMethod: 'passkey'; authContext?: { qrSessionId?: string } }
    credential: { id: string }
  }>

  authenticate(params?: {
    userId?: string
  }): Promise<{
    method: 'passkey'
    user: { id: string; email?: string }
    session: { token: string; expiresAt: string; authMethod: 'passkey'; authContext?: { qrSessionId?: string } }
  }>
}

export function createClientPasskeyManager(config: ClientConfig): ClientPasskeyManager {
  return {
    supportsPasskeys() {
      return browserSupportsWebAuthn()
    },

    supportsAutofill() {
      return browserSupportsWebAuthnAutofill()
    },

    hasPlatformAuthenticator() {
      return platformAuthenticatorIsAvailable()
    },

    async register(params) {
      const { options, userId } = await config.request<{
        options: PublicKeyCredentialCreationOptionsJSON
        userId: string
      }>('/passkey/register/options', params ?? {})

      const response = await startRegistration({ optionsJSON: options })

      return config.request('/passkey/register/verify', { userId, response })
    },

    async authenticate(params) {
      const { options } = await config.request<{
        options: PublicKeyCredentialRequestOptionsJSON
      }>('/passkey/authenticate/options', params ?? {})

      const response = await startAuthentication({ optionsJSON: options })

      return config.request('/passkey/authenticate/verify', { response })
    },
  }
}
