# @alternatefutures/e2ee

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
