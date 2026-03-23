import { describe, it, expect, vi } from 'vitest'
import { createClient } from '../src/client/index.js'

describe('createClient grouped helpers', () => {
  it('exposes account helpers through grouped namespace', async () => {
    const request = vi.fn(async (endpoint: string, body?: unknown) => {
      if (endpoint === '/account') {
        return { user: { id: 'u1', email: 'current@example.com', createdAt: new Date() } }
      }
      if (endpoint === '/account/email-available') {
        return { available: (body as { email: string }).email !== 'taken@example.com' }
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
    await client.accounts.unlinkEmail()
    await client.accounts.delete()

    expect(request).toHaveBeenCalledWith('/account/link-email', { email: 'next@example.com' })
    expect(request).toHaveBeenCalledWith('/account/unlink-email', {})
    expect(request).toHaveBeenCalledWith('/account/delete', {})
  })
})
