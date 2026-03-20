import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from '@simplewebauthn/server'
import type {
  AuthenticationResponseJSON,
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
  RegistrationResponseJSON,
} from '@simplewebauthn/server'
import { generateId as defaultGenerateId } from '../crypto.js'
import type { AuthConfig, Credential, EmailAdapter, StorageAdapter, User } from '../types.js'

/** Internal passkey manager used by `createAuth()`. */
export interface PasskeyManager {
  generateRegistrationOptions(params: {
    userId?: string
    email?: string
    userName?: string
  }): Promise<{
    options: PublicKeyCredentialCreationOptionsJSON
    userId: string
  }>

  verifyRegistration(params: {
    userId: string
    response: RegistrationResponseJSON
  }): Promise<{ user: User; credential: Credential }>

  generateAuthenticationOptions(params?: {
    userId?: string
  }): Promise<{
    options: PublicKeyCredentialRequestOptionsJSON
  }>

  verifyAuthentication(params: {
    response: AuthenticationResponseJSON
  }): Promise<{ user: User }>
}

export function createPasskeyManager(
  storage: StorageAdapter,
  config: Pick<AuthConfig<EmailAdapter | undefined>, 'rpName' | 'rpID' | 'origin' | 'challengeTTL' | 'generateId'>,
): PasskeyManager {
  const generateId = config.generateId ?? defaultGenerateId
  const challengeTTL = config.challengeTTL ?? 60_000

  return {
    async generateRegistrationOptions(params) {
      const userId = params.userId ?? generateId()
      const userName = params.userName ?? params.email ?? userId

      const existingCreds = await storage.getCredentialsByUserId(userId)

      const options = await generateRegistrationOptions({
        rpName: config.rpName,
        rpID: config.rpID,
        userName,
        excludeCredentials: existingCreds.map((c) => ({
          id: c.id,
          transports: c.transports,
        })),
        authenticatorSelection: {
          residentKey: 'preferred',
          userVerification: 'preferred',
        },
      })

      await storage.storeChallenge(`reg:${userId}`, options.challenge, challengeTTL)

      return { options, userId }
    },

    async verifyRegistration({ userId, response }) {
      const expectedChallenge = await storage.getChallenge(`reg:${userId}`)
      if (!expectedChallenge) {
        throw new Error('Registration challenge expired or not found')
      }

      const verification = await verifyRegistrationResponse({
        response,
        expectedChallenge,
        expectedOrigin: Array.isArray(config.origin) ? config.origin : [config.origin],
        expectedRPID: config.rpID,
      })

      if (!verification.verified || !verification.registrationInfo) {
        throw new Error('Registration verification failed')
      }

      await storage.deleteChallenge(`reg:${userId}`)

      const { credential: regCred, credentialDeviceType, credentialBackedUp } =
        verification.registrationInfo

      let user = await storage.getUserById(userId)
      if (!user) {
        user = await storage.createUser({
          id: userId,
          createdAt: new Date(),
        })
      }

      const credential: Credential = {
        id: regCred.id,
        userId,
        publicKey: regCred.publicKey,
        counter: regCred.counter,
        deviceType: credentialDeviceType,
        backedUp: credentialBackedUp,
        transports: regCred.transports,
        createdAt: new Date(),
      }

      await storage.createCredential(credential)

      return { user, credential }
    },

    async generateAuthenticationOptions(params) {
      let allowCredentials: { id: string; transports?: AuthenticatorTransport[] }[] | undefined

      if (params?.userId) {
        const creds = await storage.getCredentialsByUserId(params.userId)
        allowCredentials = creds.map((c) => ({
          id: c.id,
          transports: c.transports as AuthenticatorTransport[] | undefined,
        }))
      }

      const options = await generateAuthenticationOptions({
        rpID: config.rpID,
        allowCredentials,
        userVerification: 'preferred',
      })

      // Store challenge keyed by its value (for discoverable credentials where we don't know userId)
      await storage.storeChallenge(`auth:${options.challenge}`, options.challenge, challengeTTL)

      return { options }
    },

    async verifyAuthentication({ response }) {
      const credential = await storage.getCredentialById(response.id)
      if (!credential) {
        throw new Error('Credential not found')
      }

      // Extract challenge from clientDataJSON to look up our stored challenge
      const clientData = JSON.parse(
        new TextDecoder().decode(base64urlToBuffer(response.response.clientDataJSON)),
      ) as { challenge: string }

      const storedChallenge = await storage.getChallenge(`auth:${clientData.challenge}`)
      if (!storedChallenge) {
        throw new Error('Authentication challenge expired or not found')
      }

      const verification = await verifyAuthenticationResponse({
        response,
        expectedChallenge: storedChallenge,
        expectedOrigin: Array.isArray(config.origin) ? config.origin : [config.origin],
        expectedRPID: config.rpID,
        credential: {
          id: credential.id,
          publicKey: new Uint8Array(credential.publicKey) as Uint8Array<ArrayBuffer>,
          counter: credential.counter,
          transports: credential.transports,
        },
      })

      if (!verification.verified) {
        throw new Error('Authentication verification failed')
      }

      await storage.deleteChallenge(`auth:${clientData.challenge}`)

      await storage.updateCredential(credential.id, {
        counter: verification.authenticationInfo.newCounter,
      })

      const user = await storage.getUserById(credential.userId)
      if (!user) {
        throw new Error('User not found for credential')
      }

      return { user }
    },
  }
}

function base64urlToBuffer(base64url: string): ArrayBuffer {
  const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/')
  const padded = base64 + '='.repeat((4 - (base64.length % 4)) % 4)
  const binary = atob(padded)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i)
  }
  return bytes.buffer
}
