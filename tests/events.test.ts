import { describe, it, expect, vi } from 'vitest'
import { AuthEmitter } from '../src/events.js'

describe('AuthEmitter', () => {
  it('emits events to registered handlers', () => {
    const emitter = new AuthEmitter()
    const handler = vi.fn()

    emitter.on('user:created', handler)
    emitter.emit('user:created', { user: { id: '1', createdAt: new Date() } })

    expect(handler).toHaveBeenCalledOnce()
    expect(handler).toHaveBeenCalledWith({ user: { id: '1', createdAt: expect.any(Date) } })
  })

  it('supports multiple handlers', () => {
    const emitter = new AuthEmitter()
    const h1 = vi.fn()
    const h2 = vi.fn()

    emitter.on('session:created', h1)
    emitter.on('session:created', h2)
    emitter.emit('session:created', {
      session: { id: 's', token: 't', userId: 'u', expiresAt: new Date(), createdAt: new Date() },
      user: { id: 'u', createdAt: new Date() },
      method: 'passkey',
    })

    expect(h1).toHaveBeenCalledOnce()
    expect(h2).toHaveBeenCalledOnce()
  })

  it('returns unsubscribe function', () => {
    const emitter = new AuthEmitter()
    const handler = vi.fn()

    const unsub = emitter.on('user:created', handler)
    unsub()
    emitter.emit('user:created', { user: { id: '1', createdAt: new Date() } })

    expect(handler).not.toHaveBeenCalled()
  })

  it('does not throw when emitting with no handlers', () => {
    const emitter = new AuthEmitter()
    expect(() =>
      emitter.emit('user:created', { user: { id: '1', createdAt: new Date() } }),
    ).not.toThrow()
  })
})
