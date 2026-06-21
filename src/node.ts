/**
 * Optional Node WebCrypto global shim.
 *
 * The core module and `@noble/ed25519` reference the GLOBAL `crypto` (the browser
 * and Bun expose it; the core is DOM/Node-agnostic so it never imports
 * `node:crypto` itself). Node ≥20 exposes `globalThis.crypto` by default, but Node
 * 18 keeps WebCrypto on `node:crypto`'s `webcrypto` export.
 *
 * In a Node 18 process, import this side-effecting module BEFORE the core:
 *   import '@alternatefutures/e2ee/node'
 *   import { deriveRoom } from '@alternatefutures/e2ee'
 */
import { webcrypto } from 'node:crypto'

const g = globalThis as unknown as { crypto?: Crypto }
if (!g.crypto) {
  g.crypto = webcrypto as unknown as Crypto
}
