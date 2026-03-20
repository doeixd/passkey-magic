import type { BetterAuthClientPlugin } from 'better-auth/client'
import type { passkeyMagicPlugin } from './index.js'

export const passkeyMagicClientPlugin = () =>
  ({
    id: 'passkey-magic',
    $InferServerPlugin: {} as ReturnType<typeof passkeyMagicPlugin>,
  }) satisfies BetterAuthClientPlugin
