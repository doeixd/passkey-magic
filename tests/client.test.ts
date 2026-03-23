import { describe, it, expect, expectTypeOf, vi } from 'vitest'
import { createClient } from '../src/client/index.js'
import { createAuth } from '../src/server/index.js'
import { memoryAdapter } from '../src/adapters/memory.js'

describe('createClient grouped helpers', () => {
  it('exposes account helpers through grouped namespace', async () => {
    const request = vi.fn(async (endpoint: string, body?: unknown) => {
      if (endpoint === '/account') {
        return { user: { id: 'u1', email: 'current@example.com', createdAt: new Date() } }
      }
      if (endpoint === '/account/email-available') {
        return { available: (body as { email: string }).email !== 'taken@example.com' }
      }
      if (endpoint === '/account/can-link-email') {
        const email = (body as { email: string }).email
        if (email === 'bad-email') return { ok: false, reason: 'invalid_email' }
        if (email === 'taken@example.com') return { ok: false, reason: 'email_in_use' }
        return { ok: true }
      }
      if (endpoint === '/account/update') {
        return {
          user: { id: 'u1', email: 'current@example.com', createdAt: new Date(), metadata: (body as any).metadata },
        }
      }
      if (endpoint === '/account/link-email') {
        return { user: { id: 'u1', email: (body as { email: string }).email, createdAt: new Date() } }
      }
      if (endpoint === '/account/unlink-email') {
        return { user: { id: 'u1', createdAt: new Date() } }
      }
      if (endpoint === '/account/delete') {
        return { ok: true }
      }
      throw new Error(`Unexpected endpoint: ${endpoint}`)
    })

    const client = createClient({ request: request as any })

    expect((await client.accounts.get()).user.id).toBe('u1')
    expect(await client.accounts.isEmailAvailable('free@example.com')).toBe(true)
    expect(await client.accounts.canLinkEmail('current@example.com')).toEqual({ ok: true })
    expect(await client.accounts.canLinkEmail('taken@example.com')).toEqual({
      ok: false,
      reason: 'email_in_use',
    })
    expect(await client.accounts.canLinkEmail('bad-email')).toEqual({
      ok: false,
      reason: 'invalid_email',
    })

    await client.accounts.linkEmail('next@example.com')
    await client.accounts.updateMetadata({ theme: 'dark' })
    await client.accounts.unlinkEmail()
    await client.accounts.delete()

    expect(request).toHaveBeenCalledWith('/account/link-email', { email: 'next@example.com' })
    expect(request).toHaveBeenCalledWith('/account/update', { metadata: { theme: 'dark' } })
    expect(request).toHaveBeenCalledWith('/account/unlink-email', {})
    expect(request).toHaveBeenCalledWith('/account/delete', {})
  })

  it('validates the current session without requiring a token argument', async () => {
    const request = vi.fn(async (endpoint: string) => {
      if (endpoint === '/session') {
        return {
          user: { id: 'u1', createdAt: new Date() },
          session: {
            id: 's1',
            token: 'session-token',
            userId: 'u1',
            authMethod: 'passkey',
            createdAt: new Date(),
            expiresAt: new Date(Date.now() + 1000),
          },
        }
      }
      throw new Error(`Unexpected endpoint: ${endpoint}`)
    })

    const client = createClient({ request: request as any })
    const result = await client.getSession()

    expect(result?.user.id).toBe('u1')
    expect(request).toHaveBeenCalledWith('/session')
  })

  it('carries metadata generics through client and server APIs', () => {
    type UserMeta = { theme: 'dark' | 'light' }
    type CredentialMeta = { nickname: string }

    const client = createClient<UserMeta, CredentialMeta>({
      request: vi.fn(async () => ({})) as any,
    })

    expectTypeOf(client.accounts.updateMetadata).parameter(0).toEqualTypeOf<UserMeta | undefined>()
    expectTypeOf(client.passkeys.update).parameter(0).toEqualTypeOf<{
      credentialId: string
      label?: string
      metadata?: CredentialMeta
    }>()

    const auth = createAuth<UserMeta, CredentialMeta>({
      rpName: 'Test App',
      rpID: 'localhost',
      origin: 'http://localhost:3000',
      storage: memoryAdapter<UserMeta, CredentialMeta>(),
    })

    expectTypeOf(auth.accounts.updateMetadata).parameter(0).toEqualTypeOf<{
      userId: string
      metadata?: UserMeta
    }>()
    expectTypeOf(auth.passkeys.update).parameter(0).toEqualTypeOf<{
      credentialId: string
      label?: string
      metadata?: CredentialMeta
    }>()
  })
})
