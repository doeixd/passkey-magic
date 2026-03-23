import { describe, it, expect, beforeEach } from 'vitest'
import { betterAuth } from 'better-auth'
import { memoryAdapter } from 'better-auth/adapters/memory'
import { passkeyMagicPlugin } from '../src/better-auth/index.js'
import { hashToken } from '../src/crypto.js'

describe('better-auth integration', () => {
  let db: Record<string, any[]>
  let auth: any

  beforeEach(() => {
    db = {}
    auth = betterAuth({
      secret: 'test-secret-for-better-auth-integration-tests',
      baseURL: 'http://localhost:3000',
      basePath: '/api/auth',
      database: memoryAdapter(db),
      emailAndPassword: { enabled: false },
      plugins: [
        passkeyMagicPlugin({
          rpName: 'Test App',
          rpID: 'localhost',
          origin: 'http://localhost:3000',
        }),
      ],
    })
  })

  // ── Plugin loads correctly ──

  it('creates auth instance with plugin', () => {
    expect(auth).toBeDefined()
    expect(auth.handler).toBeTypeOf('function')
  })

  // ── Handler routes are registered ──

  it('handler responds to passkey-magic endpoint paths', async () => {
    // POST to register/options should be handled (not 404)
    const res = await auth.handler(
      new Request('http://localhost:3000/api/auth/passkey-magic/register/options', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({}),
      }),
    )
    // Should not be 404 — it's a valid route. May be 400 (validation) or 200.
    expect(res.status).not.toBe(404)
  })

  it('GET /passkey-magic/credentials requires authentication', async () => {
    const res = await auth.handler(
      new Request('http://localhost:3000/api/auth/passkey-magic/credentials', {
        method: 'GET',
      }),
    )
    expect(res.status).toBe(401)
  })

  it('POST /passkey-magic/authenticate/options returns registration options', async () => {
    const res = await auth.handler(
      new Request('http://localhost:3000/api/auth/passkey-magic/authenticate/options', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({}),
      }),
    )
    // Should succeed (passkey-magic generates options without needing existing credentials)
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.options).toBeDefined()
    expect(body.options.rpId).toBe('localhost')
    expect(body.options.challenge).toBeDefined()
  })

  it('POST /passkey-magic/qr/create creates a QR session', async () => {
    const res = await auth.handler(
      new Request('http://localhost:3000/api/auth/passkey-magic/qr/create', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({}),
      }),
    )
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.sessionId).toBeDefined()
    expect(typeof body.sessionId).toBe('string')
  })

  it('GET /passkey-magic/qr/status returns session status', async () => {
    // First create a QR session
    const createRes = await auth.handler(
      new Request('http://localhost:3000/api/auth/passkey-magic/qr/create', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({}),
      }),
    )
    const { sessionId, statusToken } = await createRes.json()

    // Now poll its status
    const statusRes = await auth.handler(
      new Request(`http://localhost:3000/api/auth/passkey-magic/qr/status?sessionId=${sessionId}&statusToken=${encodeURIComponent(statusToken)}`, {
        method: 'GET',
      }),
    )
    expect(statusRes.status).toBe(200)
    const status = await statusRes.json()
    expect(status.state).toBe('created')
  })

  it('POST /passkey-magic/qr/scanned marks QR session as scanned', async () => {
    // Create a QR session
    const createRes = await auth.handler(
      new Request('http://localhost:3000/api/auth/passkey-magic/qr/create', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({}),
      }),
    )
    const { sessionId, statusToken } = await createRes.json()

    // Mark it scanned
    const scanRes = await auth.handler(
      new Request('http://localhost:3000/api/auth/passkey-magic/qr/scanned', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ sessionId }),
      }),
    )
    expect(scanRes.status).toBe(200)

    // Verify status changed
    const statusRes = await auth.handler(
      new Request(`http://localhost:3000/api/auth/passkey-magic/qr/status?sessionId=${sessionId}&statusToken=${encodeURIComponent(statusToken)}`, {
        method: 'GET',
      }),
    )
    const status = await statusRes.json()
    expect(status.state).toBe('scanned')
  })

  it('GET /passkey-magic/qr/status rejects requests without status token', async () => {
    const createRes = await auth.handler(
      new Request('http://localhost:3000/api/auth/passkey-magic/qr/create', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({}),
      }),
    )
    const { sessionId } = await createRes.json()

    const statusRes = await auth.handler(
      new Request(`http://localhost:3000/api/auth/passkey-magic/qr/status?sessionId=${sessionId}`, {
        method: 'GET',
      }),
    )
    expect(statusRes.status).toBe(400)
  })

  it('POST /passkey-magic/magic-link/send fails gracefully without email adapter', async () => {
    const res = await auth.handler(
      new Request('http://localhost:3000/api/auth/passkey-magic/magic-link/send', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ email: 'test@example.com' }),
      }),
    )
    // Should fail because no email adapter is configured
    expect(res.status).toBe(400)
  })

  it('POST /passkey-magic/register/options generates registration options', async () => {
    const res = await auth.handler(
      new Request('http://localhost:3000/api/auth/passkey-magic/register/options', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ email: 'user@test.com' }),
      }),
    )
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.options).toBeDefined()
    expect(body.userId).toBeDefined()
    expect(body.options.rp.name).toBe('Test App')
    expect(body.options.rp.id).toBe('localhost')
  })

  // ── Storage bridge integration ──

  it('register/options stores challenge in passkeyChallenge table', async () => {
    const res = await auth.handler(
      new Request('http://localhost:3000/api/auth/passkey-magic/register/options', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ email: 'user@test.com' }),
      }),
    )
    expect(res.status).toBe(200)

    // The challenge should be stored in the DB via the bridged storage
    expect(db.passkeyChallenge).toBeDefined()
    expect(db.passkeyChallenge.length).toBeGreaterThan(0)
    expect(db.passkeyChallenge[0].challenge).toBeDefined()
    expect(db.passkeyChallenge[0].expiresAt).toBeDefined()
  })

  it('qr/create stores QR session in qrSession table', async () => {
    const res = await auth.handler(
      new Request('http://localhost:3000/api/auth/passkey-magic/qr/create', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({}),
      }),
    )
    const { sessionId, statusToken } = await res.json()

    expect(db.qrSession).toBeDefined()
    expect(db.qrSession.length).toBe(1)
    expect(db.qrSession[0].id).toBe(sessionId)
    expect(db.qrSession[0].state).toBe('created')
    expect(db.qrSession[0].statusTokenHash).toBe(await hashToken(statusToken))
  })

  // ── Multiple operations ──

  it('supports full QR scan flow (create → scan → poll)', async () => {
    // Create
    const createRes = await auth.handler(
      new Request('http://localhost:3000/api/auth/passkey-magic/qr/create', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({}),
      }),
    )
    const { sessionId, statusToken } = await createRes.json()

    // Poll: created
    let statusRes = await auth.handler(
      new Request(`http://localhost:3000/api/auth/passkey-magic/qr/status?sessionId=${sessionId}&statusToken=${encodeURIComponent(statusToken)}`, {
        method: 'GET',
      }),
    )
    expect((await statusRes.json()).state).toBe('created')

    // Scan
    await auth.handler(
      new Request('http://localhost:3000/api/auth/passkey-magic/qr/scanned', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ sessionId }),
      }),
    )

    // Poll: scanned
    statusRes = await auth.handler(
      new Request(`http://localhost:3000/api/auth/passkey-magic/qr/status?sessionId=${sessionId}&statusToken=${encodeURIComponent(statusToken)}`, {
        method: 'GET',
      }),
    )
    expect((await statusRes.json()).state).toBe('scanned')
  })

  it('authenticated endpoints reject unauthenticated requests', async () => {
    const endpoints = [
      { path: '/passkey-magic/add/options', method: 'POST', body: {} },
      { path: '/passkey-magic/add/verify', method: 'POST', body: { response: {} } },
      { path: '/passkey-magic/credentials', method: 'GET' },
      { path: '/passkey-magic/credentials/update', method: 'POST', body: { credentialId: 'x', label: 'y' } },
      { path: '/passkey-magic/credentials/remove', method: 'POST', body: { credentialId: 'x' } },
    ]

    for (const ep of endpoints) {
      const reqInit: RequestInit = {
        method: ep.method,
        headers: { 'content-type': 'application/json' },
      }
      if (ep.body) reqInit.body = JSON.stringify(ep.body)

      const res = await auth.handler(
        new Request(`http://localhost:3000/api/auth${ep.path}`, reqInit),
      )
      expect(res.status).toBe(401)
    }
  })
})
