# @alternatefutures/e2ee

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
