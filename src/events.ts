import type { AuthEventHandler, AuthEventMap } from './types.js'

/** Typed event emitter for auth lifecycle events. */
export class AuthEmitter {
  private listeners = new Map<keyof AuthEventMap, Set<AuthEventHandler<any>>>()

  /**
   * Subscribe to an auth event. Returns an unsubscribe function.
   *
   * @example
   * ```ts
   * const unsub = auth.on('session:created', ({ user, method }) => {
   *   console.log(`${user.id} logged in via ${method}`)
   * })
   * unsub() // stop listening
   * ```
   */
  on<K extends keyof AuthEventMap>(event: K, handler: AuthEventHandler<K>): () => void {
    if (!this.listeners.has(event)) {
      this.listeners.set(event, new Set())
    }
    this.listeners.get(event)!.add(handler)
    return () => {
      this.listeners.get(event)?.delete(handler)
    }
  }

  /** Emit an event to all registered handlers. */
  emit<K extends keyof AuthEventMap>(event: K, data: AuthEventMap[K]): void {
    const handlers = this.listeners.get(event)
    if (handlers) {
      for (const handler of handlers) {
        handler(data)
      }
    }
  }
}
