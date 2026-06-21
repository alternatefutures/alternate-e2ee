# @alternatefutures/e2ee

## 0.1.0

### Minor Changes

- 2009597: Initial release: framework-agnostic E2EE protocol core extracted from
  alternate-chat. Argon2id room derivation (`deriveRoom`/`deriveRoomBytes`/`deriveRaw`
  with `{ salt, normalize }`), AES-256-GCM message/presence sealing, Ed25519 TOFU
  identity, and the wire envelope. `deriveRoom` output is byte-identical to
  alt-chat v2. Subpaths: `.` (core), `./wordlist`, `./node` (WebCrypto shim).
