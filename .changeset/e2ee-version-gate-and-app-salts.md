---
"@alternatefutures/e2ee": minor
---

Harden the protocol without a wire-format change:

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
