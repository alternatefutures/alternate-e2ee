import { defineConfig } from 'tsup'

export default defineConfig({
  entry: ['src/index.ts', 'src/wordlist.ts', 'src/node.ts'],
  format: ['esm', 'cjs'],
  dts: true,
  clean: true,
  sourcemap: true,
  // Keep crypto deps external — consumers resolve/bundle the pinned versions.
  external: ['@noble/ed25519', 'hash-wasm', 'node:crypto'],
  target: 'es2022',
})
