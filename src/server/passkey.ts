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
    allowExistingUser?: boolean
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
      const existingUser = await storage.getUserById(userId)

      if (existingUser && !params.allowExistingUser) {
        throw new Error('Cannot start registration for an existing user without authentication')
      }

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

      await storage.storeChallenge(
        `reg:${userId}`,
        JSON.stringify({ challenge: options.challenge, allowExistingUser: params.allowExistingUser === true }),
        challengeTTL,
      )

      return { options, userId }
    },

    async verifyRegistration({ userId, response }) {
      const storedChallenge = await storage.getChallenge(`reg:${userId}`)
      if (!storedChallenge) {
        throw new Error('Registration challenge expired or not found')
      }

      const { challenge: expectedChallenge, allowExistingUser } = parseRegistrationChallenge(storedChallenge)

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
      if (user && !allowExistingUser) {
        throw new Error('Cannot register a passkey for an existing user without authentication')
      }
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

      await storage.storeChallenge(
        `auth:${options.challenge}`,
        JSON.stringify({ challenge: options.challenge, userId: params?.userId }),
        challengeTTL,
      )

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

      const storedAuthChallenge = await storage.getChallenge(`auth:${clientData.challenge}`)
      if (!storedAuthChallenge) {
        throw new Error('Authentication challenge expired or not found')
      }

      const { challenge: storedChallenge, userId: expectedUserId } = parseAuthenticationChallenge(storedAuthChallenge)
      if (expectedUserId && credential.userId !== expectedUserId) {
        throw new Error('Authentication credential does not match the requested user')
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

function parseRegistrationChallenge(value: string): { challenge: string; allowExistingUser: boolean } {
  try {
    const parsed = JSON.parse(value) as { challenge?: string; allowExistingUser?: boolean }
    if (typeof parsed.challenge === 'string') {
      return { challenge: parsed.challenge, allowExistingUser: parsed.allowExistingUser === true }
    }
  } catch {}
  return { challenge: value, allowExistingUser: false }
}

function parseAuthenticationChallenge(value: string): { challenge: string; userId?: string } {
  try {
    const parsed = JSON.parse(value) as { challenge?: string; userId?: string }
    if (typeof parsed.challenge === 'string') {
      return {
        challenge: parsed.challenge,
        userId: typeof parsed.userId === 'string' ? parsed.userId : undefined,
      }
    }
  } catch {}
  return { challenge: value }
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
