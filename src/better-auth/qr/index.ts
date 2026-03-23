import type { BetterAuthPlugin } from 'better-auth'
import { passkeyMagicPlugin, type PasskeyMagicPluginOptions } from '../index.js'
import type { MetadataObject } from '../../types.js'

const QR_SCHEMA_KEYS = ['passkeyCredential', 'qrSession', 'passkeyChallenge'] as const
const QR_ENDPOINT_KEYS = [
  'passkeyMagicQrCreate',
  'passkeyMagicQrStatus',
  'passkeyMagicQrScanned',
  'passkeyMagicQrConfirm',
  'passkeyMagicQrComplete',
] as const

export type PasskeyMagicQRPluginOptions<
  TUserMetadata extends MetadataObject = MetadataObject,
  TCredentialMetadata extends MetadataObject = MetadataObject,
> = PasskeyMagicPluginOptions<TUserMetadata, TCredentialMetadata>

/**
 * Focused Better Auth plugin that exposes only the QR cross-device login layer.
 *
 * This is additive for Better Auth apps that already use Better Auth's own
 * passkey or magic-link features and only want the QR flow from passkey-magic.
 */
export function passkeyMagicQRPlugin<
  TUserMetadata extends MetadataObject = MetadataObject,
  TCredentialMetadata extends MetadataObject = MetadataObject,
>(options: PasskeyMagicQRPluginOptions<TUserMetadata, TCredentialMetadata>): BetterAuthPlugin {
  const plugin = passkeyMagicPlugin<TUserMetadata, TCredentialMetadata>(options)

  return {
    id: 'passkey-magic-qr',
    schema: Object.fromEntries(QR_SCHEMA_KEYS.map((key) => [key, plugin.schema[key]])),
    endpoints: Object.fromEntries(QR_ENDPOINT_KEYS.map((key) => [key, plugin.endpoints[key]])),
    rateLimit: plugin.rateLimit?.filter((rule) =>
      ['/passkey-magic/qr/create', '/passkey-magic/qr/status', '/passkey-magic/qr/scanned', '/passkey-magic/qr/confirm', '/passkey-magic/qr/complete']
        .some((path) => rule.pathMatcher(path)),
    ),
  } satisfies BetterAuthPlugin
}

export type { PasskeyMagicPluginOptions } from '../index.js'
