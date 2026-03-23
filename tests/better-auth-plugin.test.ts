import { describe, it, expect, expectTypeOf, vi, beforeEach } from 'vitest'
import { passkeyMagicPlugin } from '../src/better-auth/index.js'
import { passkeyMagicClientPlugin } from '../src/better-auth/client.js'

describe('passkeyMagicPlugin', () => {
  const baseOptions = {
    rpName: 'Test App',
    rpID: 'localhost',
    origin: 'http://localhost:3000',
  }

  function makePlugin() {
    return passkeyMagicPlugin(baseOptions)
  }

  // ── Plugin Identity ──

  describe('plugin identity', () => {
    it('has correct id', () => {
      const plugin = makePlugin()
      expect(plugin.id).toBe('passkey-magic')
    })
  })

  // ── Schema ──

  describe('schema', () => {
    it('defines passkeyCredential table', () => {
      const plugin = makePlugin()
      expect(plugin.schema.passkeyCredential).toBeDefined()
      expect(plugin.schema.passkeyCredential.fields.userId).toBeDefined()
      expect(plugin.schema.passkeyCredential.fields.publicKey).toBeDefined()
      expect(plugin.schema.passkeyCredential.fields.counter).toBeDefined()
      expect(plugin.schema.passkeyCredential.fields.deviceType).toBeDefined()
      expect(plugin.schema.passkeyCredential.fields.backedUp).toBeDefined()
      expect(plugin.schema.passkeyCredential.fields.transports).toBeDefined()
      expect(plugin.schema.passkeyCredential.fields.label).toBeDefined()
      expect(plugin.schema.passkeyCredential.fields.createdAt).toBeDefined()
    })

    it('defines qrSession table', () => {
      const plugin = makePlugin()
      expect(plugin.schema.qrSession).toBeDefined()
      expect(plugin.schema.qrSession.fields.state).toBeDefined()
      expect(plugin.schema.qrSession.fields.userId).toBeDefined()
      expect(plugin.schema.qrSession.fields.expiresAt).toBeDefined()
    })

    it('defines passkeyChallenge table', () => {
      const plugin = makePlugin()
      expect(plugin.schema.passkeyChallenge).toBeDefined()
      expect(plugin.schema.passkeyChallenge.fields.key).toBeDefined()
      expect(plugin.schema.passkeyChallenge.fields.challenge).toBeDefined()
      expect(plugin.schema.passkeyChallenge.fields.expiresAt).toBeDefined()
    })

    it('defines magicLinkToken table', () => {
      const plugin = makePlugin()
      expect(plugin.schema.magicLinkToken).toBeDefined()
      expect(plugin.schema.magicLinkToken.fields.email).toBeDefined()
      expect(plugin.schema.magicLinkToken.fields.expiresAt).toBeDefined()
    })

    it('passkeyCredential references user table', () => {
      const plugin = makePlugin()
      expect(plugin.schema.passkeyCredential.fields.userId.references).toEqual({
        model: 'user',
        field: 'id',
        onDelete: 'cascade',
      })
    })

    it('passkeyChallenge key field is unique', () => {
      const plugin = makePlugin()
      expect(plugin.schema.passkeyChallenge.fields.key.unique).toBe(true)
    })
  })

  // ── Endpoints ──

  describe('endpoints', () => {
    it('defines all passkey registration endpoints', () => {
      const plugin = makePlugin()
      expect(plugin.endpoints.passkeyMagicRegisterOptions).toBeDefined()
      expect(plugin.endpoints.passkeyMagicRegisterVerify).toBeDefined()
    })

    it('defines all passkey authentication endpoints', () => {
      const plugin = makePlugin()
      expect(plugin.endpoints.passkeyMagicAuthenticateOptions).toBeDefined()
      expect(plugin.endpoints.passkeyMagicAuthenticateVerify).toBeDefined()
    })

    it('defines passkey management endpoints', () => {
      const plugin = makePlugin()
      expect(plugin.endpoints.passkeyMagicAddOptions).toBeDefined()
      expect(plugin.endpoints.passkeyMagicAddVerify).toBeDefined()
      expect(plugin.endpoints.passkeyMagicCredentials).toBeDefined()
      expect(plugin.endpoints.passkeyMagicCredentialsUpdate).toBeDefined()
      expect(plugin.endpoints.passkeyMagicCredentialsRemove).toBeDefined()
    })

    it('defines QR session endpoints', () => {
      const plugin = makePlugin()
      expect(plugin.endpoints.passkeyMagicQrCreate).toBeDefined()
      expect(plugin.endpoints.passkeyMagicQrStatus).toBeDefined()
      expect(plugin.endpoints.passkeyMagicQrScanned).toBeDefined()
      expect(plugin.endpoints.passkeyMagicQrComplete).toBeDefined()
    })

    it('defines magic link endpoints', () => {
      const plugin = makePlugin()
      expect(plugin.endpoints.passkeyMagicMagicLinkSend).toBeDefined()
      expect(plugin.endpoints.passkeyMagicMagicLinkVerify).toBeDefined()
    })

    it('defines account identity endpoints', () => {
      const plugin = makePlugin()
      expect(plugin.endpoints.passkeyMagicAccountCanLinkEmail).toBeDefined()
      expect(plugin.endpoints.passkeyMagicAccountUpdate).toBeDefined()
    })

    it('has 17 total endpoints', () => {
      const plugin = makePlugin()
      expect(Object.keys(plugin.endpoints)).toHaveLength(17)
    })

    it('defines Better Auth-native rate limit rules for sensitive endpoints when configured', () => {
      const plugin = passkeyMagicPlugin({
        ...baseOptions,
        rateLimit: {
          rules: {
            'magicLink.send': { limit: 5, windowMs: 15 * 60 * 1000 },
            'qr.create': { limit: 10, windowMs: 60 * 1000 },
          },
        },
      })

      expect(plugin.rateLimit).toBeDefined()
      expect(plugin.rateLimit).toHaveLength(2)
      expect(plugin.rateLimit?.some((rule) => rule.pathMatcher('/passkey-magic/magic-link/send') && rule.max === 5)).toBe(true)
      expect(plugin.rateLimit?.some((rule) => rule.pathMatcher('/passkey-magic/qr/create') && rule.window === 60)).toBe(true)
    })
  })
})

// ── Client Plugin ──

describe('passkeyMagicClientPlugin', () => {
  it('has correct id', () => {
    const client = passkeyMagicClientPlugin()
    expect(client.id).toBe('passkey-magic')
  })

  it('has $InferServerPlugin property', () => {
    const client = passkeyMagicClientPlugin()
    expect(client.$InferServerPlugin).toBeDefined()
  })

  it('exposes grouped client actions', async () => {
    const client = passkeyMagicClientPlugin()
    const $fetch = vi.fn(async () => ({ ok: true }))
    const actions = client.getActions?.($fetch as any)

    expect(actions?.passkeyMagic.register.options).toBeTypeOf('function')
    expect(actions?.passkeyMagic.authenticate.verify).toBeTypeOf('function')
    expect(actions?.passkeyMagic.passkeys.list).toBeTypeOf('function')
    expect(actions?.passkeyMagic.qr.status).toBeTypeOf('function')
    expect(actions?.passkeyMagic.magicLinks.send).toBeTypeOf('function')
    expect(actions?.passkeyMagic.accounts.canLinkEmail).toBeTypeOf('function')
    expect(actions?.passkeyMagic.accounts.updateMetadata).toBeTypeOf('function')

    await actions?.passkeyMagic.qr.status('qr-1', 'status-token')
    await actions?.passkeyMagic.accounts.canLinkEmail({ email: 'user@example.com' })
    await actions?.passkeyMagic.accounts.updateMetadata({ metadata: { theme: 'dark' } })

    expect($fetch).toHaveBeenCalledWith('/passkey-magic/qr/status', {
      method: 'GET',
      query: { sessionId: 'qr-1', statusToken: 'status-token' },
    })
    expect($fetch).toHaveBeenCalledWith('/passkey-magic/account/can-link-email', {
      method: 'POST',
      body: { email: 'user@example.com' },
    })
    expect($fetch).toHaveBeenCalledWith('/passkey-magic/account/update', {
      method: 'POST',
      body: { metadata: { theme: 'dark' } },
    })
  })

  it('declares path methods for typed GET routes', () => {
    const client = passkeyMagicClientPlugin()
    expect(client.pathMethods).toEqual({
      '/passkey-magic/qr/status': 'GET',
    })
  })

  it('carries metadata generics through better-auth client plugin actions', () => {
    type UserMeta = { theme: 'dark' | 'light' }
    type CredentialMeta = { nickname: string }

    const client = passkeyMagicClientPlugin<UserMeta, CredentialMeta>()
    const actions = client.getActions?.((async () => ({})) as any)

    expectTypeOf(actions?.passkeyMagic.accounts.updateMetadata).parameter(0).toEqualTypeOf<{
      metadata?: UserMeta
    }>()
    expectTypeOf(actions?.passkeyMagic.passkeys.update).parameter(0).toEqualTypeOf<{
      credentialId: string
      label?: string
      metadata?: CredentialMeta
    }>()
  })
})
