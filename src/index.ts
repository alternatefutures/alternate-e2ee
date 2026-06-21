/**
 * @alternatefutures/e2ee — the framework-agnostic end-to-end-encryption core.
 *
 * Argon2id room derivation, AES-256-GCM message/presence sealing, Ed25519 TOFU
 * identity, and the wire envelope — DOM-free, network-free, storage-free. The
 * single source of truth shared by every AlternateFutures client.
 *
 * Subpaths:
 *   '@alternatefutures/e2ee'           — this core (protocol)
 *   '@alternatefutures/e2ee/wordlist'  — room-label wordlist (roomLabel/isWord)
 *   '@alternatefutures/e2ee/node'      — Node ≤18 WebCrypto global shim (side effect)
 */
export * from './protocol'
