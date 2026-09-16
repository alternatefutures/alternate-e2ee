---
"@alternatefutures/e2ee": minor
---

New `@alternatefutures/e2ee/node-client` entry: the Node chat client (`ChatClient`: passphrase-derived room, presence, history replay, edits/deletes, reconnect, hosted-relay tickets) moved here from the `acc` CLI so the CLI and the swarm bridge share one implementation, plus `deriveIdentityFromSeed(seedHex, label)` for stable hosted participants (HKDF-SHA-256). Requires `ws`.
