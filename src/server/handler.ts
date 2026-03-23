import type { AuthInstance } from './index.js'
import type {
  AuthenticationResponseJSON,
  EmailAdapter,
  MetadataObject,
  RegistrationResponseJSON,
  User,
  Session,
} from '../types.js'

interface HandlerOptions {
  /** Route prefix. Defaults to `"/auth"`. */
  pathPrefix?: string
}

/**
 * Create a Web Standard `Request → Response` handler for all auth routes.
 *
 * Routes:
 * ```
 * POST /passkey/register/options     — Start passkey registration
 * POST /passkey/register/verify      — Complete passkey registration
 * POST /passkey/authenticate/options — Start passkey authentication
 * POST /passkey/authenticate/verify  — Complete passkey authentication
 * POST /passkey/add/options          — Start adding passkey (authed)
 * POST /passkey/add/verify           — Complete adding passkey (authed)
 * POST /magic-link/send              — Send magic link email
 * POST /magic-link/verify            — Verify magic link token
 * POST /qr/create                    — Create QR login session
 * GET  /qr/:id/status                — Poll QR session status
 * POST /qr/:id/scanned              — Mark QR session scanned
 * POST /qr/:id/complete             — Complete QR session
 * GET  /session                      — Validate current session (Bearer token)
 * DELETE /session                    — Revoke current session (Bearer token)
 * POST /session/revoke               — Revoke current session (client compatibility)
 * GET  /account                      — Get current user (authed)
 * PATCH /account                     — Update account metadata (authed)
 * POST /account/update               — Update account metadata (client compatibility)
 * GET  /account/sessions             — List user sessions (authed)
 * DELETE /account/sessions/:id       — Revoke specific session (authed)
 * POST /account/sessions/:id/delete  — Revoke specific session (client compatibility)
 * DELETE /account/sessions           — Revoke all sessions (authed)
 * POST /account/sessions/delete-all  — Revoke all sessions (client compatibility)
 * GET  /account/credentials          — List user passkeys (authed)
 * PATCH /account/credentials/:id     — Update passkey label (authed)
 * POST /account/credentials/:id      — Update passkey label (client compatibility)
 * DELETE /account/credentials/:id    — Remove passkey (authed)
 * POST /account/credentials/:id/delete — Remove passkey (client compatibility)
 * POST /account/link-email           — Link email to account (authed)
 * POST /account/unlink-email         — Unlink email from account (authed)
 * POST /account/can-link-email       — Check if current user can link email (authed)
 * POST /account/email-available      — Check email availability
 * DELETE /account                    — Delete account (authed)
 * POST /account/delete               — Delete account (client compatibility)
 * ```
 */
export function createHandler(
  auth: AuthInstance<EmailAdapter | undefined>,
  opts: HandlerOptions = {},
): (request: Request) => Promise<Response> {
  const prefix = (opts.pathPrefix ?? '/auth').replace(/\/$/, '')

  async function authenticate(request: Request): Promise<{ user: User; session: Session } | null> {
    const token = extractBearerToken(request)
    if (!token) return null
    return auth.validateSession(token)
  }

  async function requireAuth(request: Request): Promise<{ user: User; session: Session }> {
    const result = await authenticate(request)
    if (!result) throw new HttpError(401, 'Authentication required')
    return result
  }

  return async (request: Request): Promise<Response> => {
    const url = new URL(request.url, 'http://localhost')
    const path = url.pathname.startsWith(prefix)
      ? url.pathname.slice(prefix.length)
      : null

    if (path === null) {
      return json({ error: 'Not found' }, 404)
    }

    try {
      // ── Passkey Registration ──

      if (path === '/passkey/register/options' && request.method === 'POST') {
        const body = await readJSON(request)
        const result = await auth.generateRegistrationOptions({
          userId: expectOptionalString(body, 'userId'),
          email: expectOptionalString(body, 'email'),
          userName: expectOptionalString(body, 'userName'),
        })
        return json(result)
      }

      if (path === '/passkey/register/verify' && request.method === 'POST') {
        const body = await readJSON(request)
        const result = await auth.verifyRegistration({
          userId: expectString(body, 'userId'),
          response: expectObject<RegistrationResponseJSON>(body, 'response'),
        })
        return json(result)
      }

      // ── Passkey Authentication ──

      if (path === '/passkey/authenticate/options' && request.method === 'POST') {
        const body = await readJSON(request)
        const result = await auth.generateAuthenticationOptions({
          userId: expectOptionalString(body, 'userId'),
        })
        return json(result)
      }

      if (path === '/passkey/authenticate/verify' && request.method === 'POST') {
        const body = await readJSON(request)
        const result = await auth.verifyAuthentication({
          response: expectObject<AuthenticationResponseJSON>(body, 'response'),
        })
        return json(result)
      }

      // ── Add Passkey (authenticated) ──

      if (path === '/passkey/add/options' && request.method === 'POST') {
        const { user } = await requireAuth(request)
        const body = await readJSON(request)
        const result = await auth.addPasskey({
          userId: user.id,
          userName: expectOptionalString(body, 'userName'),
        })
        return json(result)
      }

      if (path === '/passkey/add/verify' && request.method === 'POST') {
        const { user } = await requireAuth(request)
        const body = await readJSON(request)
        const result = await auth.verifyAddPasskey({
          userId: user.id,
          response: expectObject<RegistrationResponseJSON>(body, 'response'),
        })
        return json(result)
      }

      // ── Magic Link ──

      if (path === '/magic-link/send' && request.method === 'POST') {
        if (!('sendMagicLink' in auth)) {
          return json({ error: 'Magic link not configured' }, 400)
        }
        const body = await readJSON(request)
        const result = await (auth as AuthInstance<EmailAdapter>).sendMagicLink({
          email: expectString(body, 'email'),
        })
        return json(result)
      }

      if (path === '/magic-link/verify' && request.method === 'POST') {
        if (!('verifyMagicLink' in auth)) {
          return json({ error: 'Magic link not configured' }, 400)
        }
        const body = await readJSON(request)
        const result = await (auth as AuthInstance<EmailAdapter>).verifyMagicLink({
          token: expectString(body, 'token'),
        })
        return json(result)
      }

      // ── QR Sessions ──

      if (path === '/qr/create' && request.method === 'POST') {
        return json(await auth.createQRSession())
      }

      const qrStatusMatch = path.match(/^\/qr\/([^/]+)\/status$/)
      if (qrStatusMatch && request.method === 'GET') {
        return json(await auth.getQRSessionStatus(qrStatusMatch[1]))
      }

      const qrScannedMatch = path.match(/^\/qr\/([^/]+)\/scanned$/)
      if (qrScannedMatch && request.method === 'POST') {
        await auth.markQRSessionScanned(qrScannedMatch[1])
        return json({ ok: true })
      }

      const qrCancelMatch = path.match(/^\/qr\/([^/]+)\/cancel$/)
      if (qrCancelMatch && request.method === 'POST') {
        await auth.cancelQRSession(qrCancelMatch[1])
        return json({ ok: true })
      }

      const qrCompleteMatch = path.match(/^\/qr\/([^/]+)\/complete$/)
      if (qrCompleteMatch && request.method === 'POST') {
        const body = await readJSON(request)
        const result = await auth.completeQRSession({
          sessionId: qrCompleteMatch[1],
          response: expectObject<AuthenticationResponseJSON>(body, 'response'),
        })
        return json(result)
      }

      // ── Session ──

      if (path === '/session' && request.method === 'GET') {
        const result = await requireAuth(request)
        return json(result)
      }

      if (path === '/session' && request.method === 'DELETE') {
        const token = extractBearerToken(request)
        if (!token) return json({ error: 'No session token' }, 401)
        await auth.revokeSession(token)
        return json({ ok: true })
      }

      if (path === '/session/revoke' && request.method === 'POST') {
        const token = extractBearerToken(request)
        if (!token) return json({ error: 'No session token' }, 401)
        await auth.revokeSession(token)
        return json({ ok: true })
      }

      // ── Account (all require auth) ──

      if (path === '/account' && request.method === 'GET') {
        const { user } = await requireAuth(request)
        return json({ user })
      }

      if (path === '/account' && request.method === 'PATCH') {
        const { user } = await requireAuth(request)
        const body = await readJSON(request)
        const result = await auth.updateUserMetadata({
          userId: user.id,
          metadata: expectOptionalMetadata(body, 'metadata'),
        })
        return json(result)
      }

      if (path === '/account/update' && request.method === 'POST') {
        const { user } = await requireAuth(request)
        const body = await readJSON(request)
        const result = await auth.updateUserMetadata({
          userId: user.id,
          metadata: expectOptionalMetadata(body, 'metadata'),
        })
        return json(result)
      }

      if (path === '/account' && request.method === 'DELETE') {
        const { user } = await requireAuth(request)
        await auth.deleteAccount(user.id)
        return json({ ok: true })
      }

      if (path === '/account/delete' && request.method === 'POST') {
        const { user } = await requireAuth(request)
        await auth.deleteAccount(user.id)
        return json({ ok: true })
      }

      if (path === '/account/sessions' && request.method === 'GET') {
        const { user } = await requireAuth(request)
        const sessions = await auth.getUserSessions(user.id)
        return json({ sessions })
      }

      if (path === '/account/sessions' && request.method === 'DELETE') {
        const { user } = await requireAuth(request)
        await auth.revokeAllSessions(user.id)
        return json({ ok: true })
      }

      if (path === '/account/sessions/delete-all' && request.method === 'POST') {
        const { user } = await requireAuth(request)
        await auth.revokeAllSessions(user.id)
        return json({ ok: true })
      }

      const sessionDeleteMatch = path.match(/^\/account\/sessions\/([^/]+)$/)
      if (sessionDeleteMatch && request.method === 'DELETE') {
        const { user } = await requireAuth(request)
        const sessions = await auth.getUserSessions(user.id)
        if (!sessions.some((session) => session.id === sessionDeleteMatch[1])) {
          throw new HttpError(404, 'Session not found')
        }
        await auth.revokeSessionById(sessionDeleteMatch[1])
        return json({ ok: true })
      }

      const sessionDeleteAliasMatch = path.match(/^\/account\/sessions\/([^/]+)\/delete$/)
      if (sessionDeleteAliasMatch && request.method === 'POST') {
        const { user } = await requireAuth(request)
        const sessions = await auth.getUserSessions(user.id)
        if (!sessions.some((session) => session.id === sessionDeleteAliasMatch[1])) {
          throw new HttpError(404, 'Session not found')
        }
        await auth.revokeSessionById(sessionDeleteAliasMatch[1])
        return json({ ok: true })
      }

      if (path === '/account/credentials' && request.method === 'GET') {
        const { user } = await requireAuth(request)
        const credentials = await auth.getUserCredentials(user.id)
        return json({ credentials })
      }

      const credPatchMatch = path.match(/^\/account\/credentials\/([^/]+)$/)
      if (credPatchMatch && (request.method === 'PATCH' || request.method === 'POST')) {
        const { user } = await requireAuth(request)
        const credentials = await auth.getUserCredentials(user.id)
        if (!credentials.some((credential) => credential.id === credPatchMatch[1])) {
          throw new HttpError(404, 'Credential not found')
        }
        const body = await readJSON(request)
        if (body.label === undefined && body.metadata === undefined) {
          throw new HttpError(400, 'Missing or invalid field: label or metadata')
        }
        await auth.updateCredential({
          credentialId: credPatchMatch[1],
          label: expectOptionalString(body, 'label'),
          metadata: expectOptionalMetadata(body, 'metadata'),
        })
        return json({ ok: true })
      }

      const credDeleteMatch = path.match(/^\/account\/credentials\/([^/]+)$/)
      if (credDeleteMatch && request.method === 'DELETE') {
        const { user } = await requireAuth(request)
        const credentials = await auth.getUserCredentials(user.id)
        if (!credentials.some((credential) => credential.id === credDeleteMatch[1])) {
          throw new HttpError(404, 'Credential not found')
        }
        await auth.removeCredential(credDeleteMatch[1])
        return json({ ok: true })
      }

      const credDeleteAliasMatch = path.match(/^\/account\/credentials\/([^/]+)\/delete$/)
      if (credDeleteAliasMatch && request.method === 'POST') {
        const { user } = await requireAuth(request)
        const credentials = await auth.getUserCredentials(user.id)
        if (!credentials.some((credential) => credential.id === credDeleteAliasMatch[1])) {
          throw new HttpError(404, 'Credential not found')
        }
        await auth.removeCredential(credDeleteAliasMatch[1])
        return json({ ok: true })
      }

      if (path === '/account/link-email' && request.method === 'POST') {
        const { user } = await requireAuth(request)
        const body = await readJSON(request)
        const result = await auth.linkEmail({
          userId: user.id,
          email: expectString(body, 'email'),
        })
        return json(result)
      }

      if (path === '/account/unlink-email' && request.method === 'POST') {
        const { user } = await requireAuth(request)
        const result = await auth.unlinkEmail({ userId: user.id })
        return json(result)
      }

      if (path === '/account/can-link-email' && request.method === 'POST') {
        const { user } = await requireAuth(request)
        const body = await readJSON(request)
        const result = await auth.accounts.canLinkEmail({
          userId: user.id,
          email: expectString(body, 'email'),
        })
        return json(result)
      }

      if (path === '/account/email-available' && request.method === 'POST') {
        const body = await readJSON(request)
        const available = await auth.isEmailAvailable(expectString(body, 'email'))
        return json({ available })
      }

      return json({ error: 'Not found' }, 404)
    } catch (err) {
      if (err instanceof HttpError) {
        return json({ error: err.message }, err.status)
      }
      const message = err instanceof Error ? err.message : 'Internal error'
      const status = isClientError(message) ? 400 : 500
      return json({ error: message }, status)
    }
  }
}

// ── Helpers ──

class HttpError extends Error {
  constructor(public status: number, message: string) {
    super(message)
  }
}

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

function extractBearerToken(request: Request): string | null {
  const header = request.headers.get('Authorization')
  if (header?.startsWith('Bearer ')) return header.slice(7)
  return null
}

async function readJSON(request: Request): Promise<Record<string, unknown>> {
  try {
    const body = await request.json()
    if (typeof body !== 'object' || body === null || Array.isArray(body)) {
      throw new HttpError(400, 'Request body must be a JSON object')
    }
    return body as Record<string, unknown>
  } catch (err) {
    if (err instanceof HttpError) throw err
    throw new HttpError(400, 'Invalid JSON in request body')
  }
}

function expectString(body: Record<string, unknown>, key: string): string {
  const value = body[key]
  if (typeof value !== 'string' || value.length === 0) {
    throw new HttpError(400, `Missing or invalid field: ${key}`)
  }
  return value
}

function expectOptionalString(body: Record<string, unknown>, key: string): string | undefined {
  const value = body[key]
  if (value === undefined || value === null) return undefined
  if (typeof value !== 'string') {
    throw new HttpError(400, `Invalid field: ${key} (expected string)`)
  }
  return value
}

function expectObject<T = Record<string, unknown>>(body: Record<string, unknown>, key: string): T {
  const value = body[key]
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new HttpError(400, `Missing or invalid field: ${key}`)
  }
  return value as T
}

function expectOptionalMetadata(body: Record<string, unknown>, key: string): MetadataObject | undefined {
  const value = body[key]
  if (value === undefined || value === null) return undefined
  if (typeof value !== 'object' || Array.isArray(value)) {
    throw new HttpError(400, `Invalid field: ${key} (expected object)`)
  }
  return value as MetadataObject
}

/** Known client-side errors that should return 400 instead of 500. */
function isClientError(message: string): boolean {
  const patterns = [
    'not found', 'expired', 'invalid', 'blocked', 'already',
    'cannot remove', 'cannot unlink', 'no email', 'no passkey',
  ]
  const lower = message.toLowerCase()
  return patterns.some((p) => lower.includes(p))
}
