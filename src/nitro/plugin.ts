import type { AuthHooks, EmailAdapter, StorageAdapter } from '../types.js'
import type { Storage } from 'unstorage'
import { createAuth, type AuthInstance } from '../server/index.js'
import { unstorageAdapter } from '../adapters/unstorage.js'

export interface PasskeyMagicNitroOptions<TEmail extends EmailAdapter | undefined = undefined> {
  /** Relying party name shown to users during passkey prompts */
  rpName: string
  /** Relying party ID — typically the domain (e.g. "example.com") */
  rpID: string
  /** Expected origin(s) for WebAuthn verification */
  origin: string | string[]
  /**
   * Storage for auth data. Accepts either:
   * - An unstorage `Storage` instance (e.g. from `useStorage()`) — automatically wrapped
   * - A passkey-magic `StorageAdapter` for full control
   */
  storage?: Storage | StorageAdapter
  /** Optional email adapter to enable magic link fallback */
  email?: TEmail
  /** Base URL for magic link verification (required if email is provided) */
  magicLinkURL?: string
  /** Route prefix for the auth handler. Defaults to "/auth" */
  pathPrefix?: string
  /** unstorage key prefix for all auth data. Defaults to "auth" */
  storageBase?: string
  /** Session TTL in ms. Defaults to 7 days */
  sessionTTL?: number
  /** Challenge TTL in ms. Defaults to 60 seconds */
  challengeTTL?: number
  /** Magic link TTL in ms. Defaults to 15 minutes */
  magicLinkTTL?: number
  /** QR session TTL in ms. Defaults to 5 minutes */
  qrSessionTTL?: number
  /** Custom ID generator */
  generateId?: () => string
  /** Lifecycle hooks */
  hooks?: AuthHooks
}

// Global auth instance — set during plugin init, accessed via useAuth()
let _authInstance: AuthInstance<any> | null = null

/**
 * Get the auth instance created by the Nitro plugin.
 * Use this in route handlers to access auth methods.
 *
 * @example
 * ```ts
 * import { useAuth } from 'passkey-magic/nitro'
 *
 * export default defineHandler(async (event) => {
 *   const auth = useAuth()
 *   const session = await auth.validateSession(token)
 * })
 * ```
 */
export function useAuth<TEmail extends EmailAdapter | undefined = undefined>(): AuthInstance<TEmail> {
  if (!_authInstance) {
    throw new Error(
      'passkey-magic: auth not initialized. Make sure the Nitro plugin is registered.',
    )
  }
  return _authInstance as AuthInstance<TEmail>
}

function isUnstorageInstance(obj: any): obj is Storage {
  return obj && typeof obj.getItem === 'function' && typeof obj.setItem === 'function'
    && typeof obj.removeItem === 'function' && !('createUser' in obj)
}

function resolveStorageAdapter(
  storage: Storage | StorageAdapter | undefined,
  storageBase?: string,
): StorageAdapter {
  if (!storage) {
    throw new Error(
      'passkey-magic: storage is required. Pass a unstorage instance (e.g. useStorage()) ' +
      'or a passkey-magic StorageAdapter.',
    )
  }

  if (isUnstorageInstance(storage)) {
    return unstorageAdapter(storage, { base: storageBase })
  }

  return storage as StorageAdapter
}

/**
 * Create a passkey-magic Nitro plugin.
 *
 * Registers auth routes under the configured path prefix and makes
 * the auth instance available via `useAuth()` in route handlers.
 *
 * @example
 * ```ts
 * // plugins/auth.ts
 * import { definePlugin } from 'nitro'
 * import { useStorage } from 'nitro/storage'
 * import { passkeyMagic } from 'passkey-magic/nitro'
 *
 * export default definePlugin((nitroApp) => {
 *   passkeyMagic({
 *     rpName: 'My App',
 *     rpID: 'example.com',
 *     origin: 'https://example.com',
 *     storage: useStorage(),
 *   }).setup(nitroApp)
 * })
 * ```
 */
export function passkeyMagic<TEmail extends EmailAdapter | undefined = undefined>(
  options: PasskeyMagicNitroOptions<TEmail>,
) {
  const pathPrefix = options.pathPrefix ?? '/auth'

  function setup(nitroApp: NitroApp) {
    const adapter = resolveStorageAdapter(options.storage, options.storageBase)

    const auth = createAuth({
      rpName: options.rpName,
      rpID: options.rpID,
      origin: options.origin,
      storage: adapter,
      email: options.email,
      magicLinkURL: options.magicLinkURL,
      sessionTTL: options.sessionTTL,
      challengeTTL: options.challengeTTL,
      magicLinkTTL: options.magicLinkTTL,
      qrSessionTTL: options.qrSessionTTL,
      generateId: options.generateId,
      hooks: options.hooks,
    } as any)

    _authInstance = auth

    // Create the Web Request/Response handler
    const handler = auth.createHandler({ pathPrefix })

    // Hook into Nitro's request lifecycle
    nitroApp.hooks.hook('request', async (event: any) => {
      const pathname = event.path ?? event.req?.url ?? '/'
      if (!pathname.startsWith(pathPrefix)) return

      // Build a Web Request from the H3 event
      const request = toWebRequest(event)
      const response = await handler(request)

      // Write the response back to the H3 event
      await writeWebResponse(event, response)
    })

    // Clean up on shutdown
    nitroApp.hooks.hook('close', async () => {
      _authInstance = null
    })

    return auth
  }

  return { setup }
}

// ── Helpers for Nitro/H3 interop ──

function toWebRequest(event: any): Request {
  const req = event.req ?? event.node?.req
  const method = req?.method ?? event.method ?? 'GET'
  const url = `http://localhost${event.path ?? req?.url ?? '/'}`
  const headers = new Headers()

  if (req?.headers) {
    for (const [key, value] of Object.entries(req.headers)) {
      if (value) headers.set(key, Array.isArray(value) ? value.join(', ') : value as string)
    }
  }

  const init: RequestInit = { method, headers }
  if (method !== 'GET' && method !== 'HEAD') {
    if (event._body !== undefined) {
      init.body = JSON.stringify(event._body)
    } else if (req?.body) {
      init.body = req.body
    }
  }

  return new Request(url, init)
}

async function writeWebResponse(event: any, response: Response): Promise<void> {
  const res = event.res ?? event.node?.res

  if (res && typeof res.writeHead === 'function') {
    const headers: Record<string, string> = {}
    response.headers.forEach((value, key) => {
      headers[key] = value
    })
    res.writeHead(response.status, headers)
    const body = await response.text()
    res.end(body)
  } else if (event.respondWith) {
    await event.respondWith(response)
  }
}

// Minimal Nitro app interface to avoid hard dependency on nitro
interface NitroApp {
  hooks: {
    hook: (event: string, handler: (...args: any[]) => any) => () => void
  }
  h3?: any
  fetch?: any
}
