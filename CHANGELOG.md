# @alternatefutures/e2ee

## 0.3.0

### Minor Changes

- Non-extractable WebCrypto Ed25519 identities (XSS key-theft hardening), wire-compatible with the raw-bytes path:

  - `Identity` now carries EITHER `priv` (raw 32-byte key — CLI 0600 file, legacy
    localStorage) OR `signKey` (a WebCrypto `CryptoKey`, intended to be created
    **non-extractable** and persisted in IndexedDB). `sealMessage`/`sealPresence`
    sign with whichever is present; Ed25519 is deterministic (RFC 8032), so both
    paths emit byte-identical signatures for the same key — mixed rooms
    (CLI raw-bytes ↔ hardened browser) interoperate with no wire change and no
    `PROTOCOL_VERSION` bump.
  - New: `generateNonExtractableIdentity()` (fresh non-extractable keypair),
    `importPrivateKeyAsSignKey(priv)` (migrate an EXISTING localStorage key to a
    non-extractable CryptoKey — same pub/fingerprint/signatures, then delete the
    raw copy), `identityFromSignKey(signKey, pub)` (IndexedDB reload path), and
    `supportsWebCryptoEd25519()` (capability gate; fall back to the raw path on
    runtimes without WebCrypto Ed25519 — pre-137 Chrome etc.).
  - Type note: `Identity.priv` is now optional. Consumers that READ `.priv`
    directly (there should be none outside identity persistence) must
    null-check.
  - Dependencies pinned exact (`@noble/ed25519@2.3.0`, `hash-wasm@4.12.0`) —
    supply-chain pinning at the source so consumers inherit exact versions.

## 0.2.0

### Minor Changes

- bde6d59: Harden the protocol without a wire-format change:

  - `openMessage` now rejects envelopes whose `v` is not in `SUPPORTED_VERSIONS`
    **before** any decrypt/verify work, so a mismatched or downgraded version fails
    with a clear `unsupported protocol version: <v>` error instead of an opaque
    AES-GCM/signature failure. v2↔v2 exchanges are byte-identical (no wire change,
    hence minor not major).
  - Export `SUPPORTED_VERSIONS` (currently `{PROTOCOL_VERSION}`) so a future
    wire-compatible version is added in one place alongside the `PROTOCOL_VERSION`
    bump.
  - Export `APP_SALTS` — the single source of truth for per-app KDF salts
    (`chat: 'alt-chat/room/v2'`, `connect: 'alternate-connect/meet/v1'`). Consumers
    (e.g. `alternate-connect/lib/room.ts`) should import `APP_SALTS.connect` instead
    of hardcoding the literal once they pin this release, so a future rename is a
    compile-time break rather than a silent key-derivation divergence.
  - Add a known-answer test vector for the Argon2id KDF output plus invariant tests
    (version gate, AAD/signature binding, IV uniqueness, salt separation).

## 0.1.1

### Patch Changes

- a6b367d: Fix dual-package exports for CommonJS / node16 consumers. Each subpath now uses
  per-condition types (`import` → `.d.ts`, `require` → `.d.cts`) so a CJS consumer
  under `moduleResolution: node16/nodenext` (the `acc` CLI) resolves the package
  without TS1479. Also expose `./package.json`.

## 0.1.0

### Minor Changes

- 2009597: Initial release: framework-agnostic E2EE protocol core extracted from
  alternate-chat. Argon2id room derivation (`deriveRoom`/`deriveRoomBytes`/`deriveRaw`
  with `{ salt, normalize }`), AES-256-GCM message/presence sealing, Ed25519 TOFU
  identity, and the wire envelope. `deriveRoom` output is byte-identical to
  alt-chat v2. Subpaths: `.` (core), `./wordlist`, `./node` (WebCrypto shim).
