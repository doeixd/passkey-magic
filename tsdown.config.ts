import { defineConfig } from 'tsdown'

export default defineConfig({
  entry: [
    'src/server/index.ts',
    'src/client/index.ts',
    'src/adapters/memory.ts',
    'src/adapters/unstorage.ts',
    'src/nitro/index.ts',
    'src/better-auth/index.ts',
    'src/better-auth/client.ts',
    'src/better-auth/qr/index.ts',
    'src/better-auth/qr/client.ts',
  ],
  format: 'esm',
  dts: true,
  clean: true,
})
