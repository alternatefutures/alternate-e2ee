# @alternatefutures/e2ee

The framework-agnostic **end-to-end-encryption core** shared across AlternateFutures
clients (alternate-chat, the `acc` CLI, alternate-connect video, and future
services). DOM-free, network-free, storage-free — it runs unchanged in the
browser, Bun, and Node.

This package is the **single source of truth** for the protocol. It replaces the
previous "edit two byte-identical `protocol.ts` copies and `diff` them" rule:
there is now one copy, imported at a pinned version. Interop is enforced by the
lockfile, not by reviewer vigilance.

## What's inside

- **Room derivation** — `deriveRoom` (→ WebCrypto `CryptoKey` + room id),
  `deriveRoomBytes` (→ raw 32-byte key + room id, for e.g. LiveKit `setKey`),
  `deriveRaw` (the raw 64-byte Argon2id output). The passphrase *is* the room.
- **Identity** — Ed25519 TOFU: `randomPrivateKey`, `identityFromPrivateKey`,
  `fingerprintOf`.
- **Envelope** — `sealMessage`/`openMessage`, `sealPresence`/`openPresence`
  (AES-256-GCM, AAD-bound, length-padded, Ed25519-signed).
- **Constants/helpers** — `PROTOCOL_VERSION`, `ARGON2_PARAMS`, `ROOM_SALT`,
  `ROOM_ID_RE`, `toB64`/`fromB64`/`toB64Url`.

## Install

```bash
npm i @alternatefutures/e2ee
```

## Use

```ts
import { deriveRoom, identityFromPrivateKey, randomPrivateKey, sealMessage } from '@alternatefutures/e2ee'

const { key, roomId } = await deriveRoom('a strong shared passphrase')
const me = await identityFromPrivateKey(randomPrivateKey())
const envelope = await sealMessage(key, me, roomId, 1, 'alice', 'hello')
```

Per-app domain separation (so a reused passphrase does NOT collide across apps):

```ts
import { deriveRoomBytes } from '@alternatefutures/e2ee'
// video app: distinct salt + NFKC, raw key bytes for LiveKit
const { keyBytes, roomId } = await deriveRoomBytes(passphrase, {
  salt: 'alternate-connect/meet/v1',
  normalize: true,
})
```

Subpaths:

```ts
import { roomLabel } from '@alternatefutures/e2ee/wordlist' // human room labels
import '@alternatefutures/e2ee/node'                        // Node ≤18 WebCrypto shim (import FIRST)
```

> **Defaults are byte-identical to alt-chat v2** (`salt = 'alt-chat/room/v2'`, no
> NFKC), so adopting this package invalidates no existing room.

## Security & versioning

The KDF params, AAD layout, padding buckets, and signed-bytes layout are
**protocol constants** — every participant in a room must produce identical
bytes. Any change to them is wire-breaking: bump **`PROTOCOL_VERSION`** *and* the
package version (minor/major) together, and pin the exact version across all
consumers. Keys never leave this layer's callers; persistence (browser
`localStorage`, CLI 0600 file) is each app's concern. `@noble/ed25519` and
`hash-wasm` are pinned; published with `--provenance`.

## Develop

```bash
npm install
npm run typecheck
npm run build     # tsup → dist (ESM + CJS + .d.ts)
npm test          # vitest: determinism, salt separation, seal/open round-trip
```
