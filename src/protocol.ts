/**
 * alt-chat protocol — the portable, DOM-free core of the end-to-end-encrypted
 * chat. EVERYTHING that touches a key, ciphertext, or signature lives here, and
 * NOTHING here touches the DOM, the network, or any storage. It runs unchanged
 * in the browser, in Bun, and in Node (the `acc` CLI + autonomous agents) — which
 * is the whole point: every client in a room MUST derive the same key + room id
 * and emit the same envelope bytes, or they simply cannot talk to each other.
 *
 * ┌─ SOURCE OF TRUTH ──────────────────────────────────────────────────────────┐
 * │ This is the canonical source, published as `@alternatefutures/e2ee`. Every  │
 * │ client (alternate-chat browser, the `acc` CLI, alternate-connect video,     │
 * │ future services) imports it — there are NO hand-mirrored copies.            │
 * │ The KDF + its params, the AAD layout, the padding buckets, and the signed-  │
 * │ bytes layout are PROTOCOL CONSTANTS: every participant in a room must derive │
 * │ the same key + room id and emit the same envelope bytes. Any change to those │
 * │ is a wire-breaking change — bump PROTOCOL_VERSION *and* the package version  │
 * │ (minor/major) together; interop is then enforced by consumers' lockfiles.   │
 * └────────────────────────────────────────────────────────────────────────────┘
 *
 * Model (v2 — passphrase-only):
 *   - Room key + room id = Argon2id(passphrase, salt = SHA-256(ROOM_SALT)) → 64
 *     bytes, split into a 32-byte AES-256-GCM key ‖ a 32-byte opaque room id.
 *     The salt is a FIXED app constant, so the passphrase ALONE selects the room
 *     — there is no separate room name. (v1 used SHA-256(roomName) as the salt;
 *     bumping the version invalidates v1 rooms, which is intended.)
 *   - Each message: fresh 12-byte IV, AES-256-GCM over a length-prefixed,
 *     bucket-padded plaintext. AAD binds {version, room, epoch, seq, pubkey}
 *     so a ciphertext can't be replayed into another room / seq.
 *   - Sender authenticity: an Ed25519 keypair (TOFU). Every message is signed
 *     over {version, room, epoch, seq, iv, ciphertext}. The username is carried
 *     *inside* the ciphertext, not on the wire.
 *
 * IMPORTANT — interoperability: the KDF and its parameters are PROTOCOL
 * CONSTANTS, identical for every client in a room. There is no per-client
 * runtime fallback to PBKDF2 (that would derive a different key and break the
 * room). PBKDF2 is implemented as a *protocol-version* alternative only; a
 * future `v` bump could select it. The envelope's `v` field gates this.
 *
 * Forward-compat (MLS, RFC 9420): the envelope already carries `epoch` and a
 * version tag, so MLS slots in as a future version bump, not a breaking change.
 */
import * as ed from '@noble/ed25519'
import { argon2id } from 'hash-wasm'

// Wire Ed25519 to WebCrypto's SHA-512 (no extra hash dependency). Resolves
// against the global `crypto.subtle`, which exists in the browser, in Bun, and
// in Node ≥18 (the CLI installs a `node:crypto` webcrypto shim on the global
// before importing this module, so the reference below is always satisfied).
ed.etc.sha512Async = async (...m: Uint8Array[]) =>
  new Uint8Array(await crypto.subtle.digest('SHA-512', ed.etc.concatBytes(...m)))

// ── Protocol constants ──────────────────────────────────────────────────────
export const PROTOCOL_VERSION = 2
/** Envelope `v` values this build knows how to open. Only the current version is
 *  live (v1 rooms are intentionally invalidated). A future wire-compatible bump
 *  adds its number here in the same commit that bumps PROTOCOL_VERSION. Used by
 *  openMessage to fail fast + legibly on an unsupported version instead of
 *  falling through to an opaque AES-GCM/signature error. */
export const SUPPORTED_VERSIONS: ReadonlySet<number> = new Set([PROTOCOL_VERSION])
export const KDF = 'argon2id' as const
// OWASP "first recommended" Argon2id config: 19 MiB, t=2, p=1 → ~32B key.
export const ARGON2_PARAMS = { memorySize: 19_456, iterations: 2, parallelism: 1, hashLength: 32 }
// PBKDF2 alternative (only if a future protocol version selects it).
export const PBKDF2_ITERATIONS = 600_000
// Fixed KDF salt — the passphrase alone selects the room (no room name). Public
// by design (a salt isn't secret); domain-separates this app's key derivation.
export const ROOM_SALT = 'alt-chat/room/v2'
/** Per-app KDF salts. Each app MUST use a distinct salt so a passphrase reused
 *  across apps derives DIFFERENT keys/room ids (no cross-app collision). This is
 *  the single source of truth — consumers import from here instead of hardcoding
 *  the literal, so any future rename is a compile-time break, not silent runtime
 *  divergence. Invariant: all values are pairwise distinct (see protocol tests). */
export const APP_SALTS = {
  chat: ROOM_SALT, // 'alt-chat/room/v2'
  connect: 'alternate-connect/meet/v1',
} as const
// Fixed padding buckets (bytes) for the *plaintext* before encryption.
const PAD_BUCKETS = [256, 1024, 4096, 16_384]
const DOMAIN = new TextEncoder().encode('alt-chat/v1')

// ── Encoding helpers ─────────────────────────────────────────────────────────
const enc = new TextEncoder()
const dec = new TextDecoder()

export function toB64(b: Uint8Array): string {
  let s = ''
  for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i])
  return btoa(s)
}
export function fromB64(s: string): Uint8Array {
  const bin = atob(s)
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}
export function toB64Url(b: Uint8Array): string {
  return toB64(b).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}
/** Shape of a derived room id: base64url of 32 bytes = 43 chars (no padding). */
export const ROOM_ID_RE = /^[A-Za-z0-9_-]{43}$/
function toHex(b: Uint8Array): string {
  return Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('')
}
function concat(...arrs: Uint8Array[]): Uint8Array {
  let len = 0
  for (const a of arrs) len += a.length
  const out = new Uint8Array(len)
  let off = 0
  for (const a of arrs) {
    out.set(a, off)
    off += a.length
  }
  return out
}
function u64(n: number): Uint8Array {
  const b = new Uint8Array(8)
  new DataView(b.buffer).setBigUint64(0, BigInt(n), false)
  return b
}
async function sha256(data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', data))
}

// ── Room id + key derivation ─────────────────────────────────────────────────

export type Room = { key: CryptoKey; roomId: string }

/**
 * Options for room derivation. Defaults reproduce alt-chat v2 EXACTLY, so the
 * default `deriveRoom`/`deriveRaw` output is byte-identical to the pre-package
 * implementation (no existing room is invalidated by adopting this package).
 *
 *   salt      — KDF domain-separation string (hashed to the Argon2id salt).
 *               Per-app so a passphrase reused across apps does NOT collide
 *               rooms/keys (chat: 'alt-chat/room/v2'; video: 'alternate-connect/meet/v1').
 *   normalize — apply Unicode NFKC to the passphrase first. Off by default
 *               (alt-chat does not normalize); on for newer consumers so visually
 *               identical passphrases derive the same key cross-platform.
 */
export type DeriveOpts = { salt?: string; normalize?: boolean }

/**
 * The raw 64-byte Argon2id output: bytes[0..32) = AES-256-GCM key material,
 * bytes[32..64) = opaque room id material. The lowest-level primitive — every
 * consumer builds on this. Chat wraps it into a `CryptoKey` (`deriveRoom`); the
 * video app feeds the raw key bytes to LiveKit's `ExternalE2EEKeyProvider`
 * (`deriveRoomBytes`). With default opts this is exactly alt-chat's derivation.
 */
export async function deriveRaw(password: string, opts: DeriveOpts = {}): Promise<Uint8Array> {
  const pw = opts.normalize ? password.normalize('NFKC') : password
  const salt = await sha256(enc.encode(opts.salt ?? ROOM_SALT))
  return argon2id({
    password: pw,
    salt,
    parallelism: ARGON2_PARAMS.parallelism,
    iterations: ARGON2_PARAMS.iterations,
    memorySize: ARGON2_PARAMS.memorySize,
    hashLength: 64, // 32B key ‖ 32B room id
    outputType: 'binary',
  })
}

/**
 * Derive the room key bytes (32B, never sent) + opaque room id (base64url, the
 * only thing the relay sees) from the passphrase. For consumers that need raw key
 * bytes rather than a WebCrypto `CryptoKey` (e.g. LiveKit `setKey`).
 */
export async function deriveRoomBytes(
  password: string,
  opts: DeriveOpts = {},
): Promise<{ keyBytes: Uint8Array; roomId: string }> {
  const raw = await deriveRaw(password, opts)
  return { keyBytes: raw.slice(0, 32), roomId: toB64Url(raw.slice(32, 64)) }
}

/**
 * Derive BOTH the AES-256-GCM room key (as a WebCrypto `CryptoKey`) AND the
 * opaque wire room id from the passphrase ALONE, in a single Argon2id pass.
 *
 * The passphrase is the room: a wrong passphrase yields a DIFFERENT room id → you
 * land in a different, isolated relay topic and never receive (or even observe)
 * the real room's ciphertext. The id is a KDF output, so brute-forcing a weak
 * passphrase from a captured id costs the full Argon2id work factor; the two
 * halves are independent, so the public id does not reveal the key. Security
 * therefore rests entirely on passphrase entropy — keep it strong.
 */
export async function deriveRoom(password: string, opts: DeriveOpts = {}): Promise<Room> {
  const raw = await deriveRaw(password, opts)
  const key = await crypto.subtle.importKey('raw', raw.slice(0, 32), { name: 'AES-GCM' }, false, [
    'encrypt',
    'decrypt',
  ])
  return { key, roomId: toB64Url(raw.slice(32, 64)) }
}

/** PBKDF2 alternative — NOT used at runtime; kept for a future `v` bump.
 *  A real switch would mirror deriveRoom (derive 64B, split key ‖ room id). */
export async function deriveRoomKeyPbkdf2(password: string): Promise<CryptoKey> {
  const salt = await sha256(enc.encode(ROOM_SALT))
  const base = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, [
    'deriveKey',
  ])
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  )
}

// ── Identity (Ed25519, TOFU) ──────────────────────────────────────────────────
// The protocol layer is storage-agnostic: it only knows how to turn signing
// material into a full identity. WHERE that material is persisted is an
// environment concern — the CLI uses a 0600 file (raw bytes), browsers should
// use a NON-EXTRACTABLE WebCrypto key in IndexedDB — so each environment stores
// only the signing material and rebuilds the rest here. That keeps the public
// key, fingerprint, and therefore every signature identical across environments
// for the same key (Ed25519 is deterministic per RFC 8032: the raw-bytes path
// and the WebCrypto path emit byte-identical signatures for the same key+bytes).

export type Identity = {
  /** Raw 32-byte private key — the extractable path (CLI 0600 file, legacy
   *  browser localStorage). Absent when the identity is WebCrypto-backed. */
  priv?: Uint8Array
  /** WebCrypto Ed25519 private key — create it NON-EXTRACTABLE in the browser:
   *  same-origin script (i.e. XSS) can then still *use* the key to sign, but can
   *  never READ the key material, so the identity cannot be exfiltrated and
   *  impersonation ends when the injected code stops running. Absent on the
   *  raw-bytes path. Exactly one of `priv`/`signKey` should be set. */
  signKey?: CryptoKey
  pub: Uint8Array
  pubB64: string
  fingerprint: string // short hex of SHA-256(pub), grouped for display
}

/** A fresh, cryptographically-random Ed25519 private key (32 bytes). */
export function randomPrivateKey(): Uint8Array {
  return ed.utils.randomPrivateKey()
}

/** Build a full identity (public key + fingerprint) from a raw private key. */
export async function identityFromPrivateKey(priv: Uint8Array): Promise<Identity> {
  const pub = await ed.getPublicKeyAsync(priv)
  return { priv, pub, pubB64: toB64(pub), fingerprint: await fingerprintOf(pub) }
}

/** True when this runtime's WebCrypto can generate + sign with Ed25519 keys
 *  (Chrome 137+, Safari 17+, Firefox 129+, Node ≥19, Bun). Apps gate the
 *  non-extractable keystore on this and fall back to the raw-bytes path where
 *  it's missing — the two paths interoperate freely on the wire. */
export async function supportsWebCryptoEd25519(): Promise<boolean> {
  try {
    const pair = (await crypto.subtle.generateKey('Ed25519', false, [
      'sign',
      'verify',
    ])) as CryptoKeyPair
    await crypto.subtle.sign('Ed25519', pair.privateKey, new Uint8Array(1))
    return true
  } catch {
    return false
  }
}

/** Generate a fresh identity whose private key is a NON-EXTRACTABLE WebCrypto
 *  key. Persist `identity.signKey` (a CryptoKey is structured-cloneable, so it
 *  stores directly in IndexedDB) plus `identity.pub`, and rebuild on load with
 *  `identityFromSignKey`. The key material itself never exists in JS memory. */
export async function generateNonExtractableIdentity(): Promise<Identity> {
  const pair = (await crypto.subtle.generateKey('Ed25519', false, [
    'sign',
    'verify',
  ])) as CryptoKeyPair
  const pub = new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey))
  return { signKey: pair.privateKey, pub, pubB64: toB64(pub), fingerprint: await fingerprintOf(pub) }
}

/** Rebuild a full identity from a persisted WebCrypto private key + raw public
 *  key bytes — the IndexedDB reload path. */
export async function identityFromSignKey(signKey: CryptoKey, pub: Uint8Array): Promise<Identity> {
  return { signKey, pub, pubB64: toB64(pub), fingerprint: await fingerprintOf(pub) }
}

// PKCS#8 wrapper for a raw Ed25519 seed (RFC 5958 outer structure, RFC 8410
// OID 1.3.101.112): a fixed 16-byte header followed by the 32-byte seed. This
// is the only import format WebCrypto accepts for Ed25519 private keys ('raw'
// import exists for PUBLIC keys only).
const PKCS8_ED25519_PREFIX = Uint8Array.from([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
])

/** Import an EXISTING raw private key as a (default non-extractable) WebCrypto
 *  signing key — the localStorage → IndexedDB migration path. Same key bytes →
 *  same public key, fingerprint, and signatures, so peers see no change; after
 *  persisting the returned `signKey`, DELETE the raw-bytes copy. */
export async function importPrivateKeyAsSignKey(
  priv: Uint8Array,
  opts: { extractable?: boolean } = {},
): Promise<Identity> {
  const signKey = await crypto.subtle.importKey(
    'pkcs8',
    concat(PKCS8_ED25519_PREFIX, priv) as BufferSource,
    'Ed25519',
    opts.extractable ?? false,
    ['sign'],
  )
  const pub = await ed.getPublicKeyAsync(priv)
  return { signKey, pub, pubB64: toB64(pub), fingerprint: await fingerprintOf(pub) }
}

/** Sign with whichever material the identity carries. Both paths produce the
 *  SAME bytes for the same key+message (RFC 8032 deterministic signatures), so
 *  mixed rooms (CLI raw-bytes ↔ browser WebCrypto) verify seamlessly. */
async function signWithIdentity(identity: Identity, bytes: Uint8Array): Promise<Uint8Array> {
  if (identity.signKey) {
    return new Uint8Array(
      await crypto.subtle.sign('Ed25519', identity.signKey, bytes as BufferSource),
    )
  }
  if (identity.priv) return ed.signAsync(bytes, identity.priv)
  throw new Error('identity has no signing material (neither signKey nor priv)')
}

/** Human-comparable short fingerprint, e.g. "a1b2 c3d4 e5f6". */
export async function fingerprintOf(pub: Uint8Array): Promise<string> {
  const h = toHex(await sha256(pub)).slice(0, 12)
  return `${h.slice(0, 4)} ${h.slice(4, 8)} ${h.slice(8, 12)}`
}

// ── Padding ──────────────────────────────────────────────────────────────────
// Prefix the real length (4 bytes BE) then zero-pad up to the next bucket. This
// hides exact message length on the wire (all messages look like one of a few
// fixed sizes). Stripped after decryption.
function pad(plain: Uint8Array): Uint8Array {
  const needed = plain.length + 4
  let bucket = PAD_BUCKETS.find((b) => b >= needed)
  if (bucket === undefined) {
    // Larger than the biggest bucket: round up to a multiple of 16 KiB.
    bucket = Math.ceil(needed / 16_384) * 16_384
  }
  const out = new Uint8Array(bucket)
  new DataView(out.buffer).setUint32(0, plain.length, false)
  out.set(plain, 4)
  return out
}
function unpad(padded: Uint8Array): Uint8Array {
  const len = new DataView(padded.buffer, padded.byteOffset, padded.byteLength).getUint32(0, false)
  if (len > padded.length - 4) throw new Error('corrupt padding')
  return padded.slice(4, 4 + len)
}

// ── Message metadata (replies / edits / deletes) ─────────────────────────────
// These ride INSIDE the encrypted plaintext, so the relay never sees who replied
// to whom or that anything was edited. A message is identified by (pubkey, seq).
// Edits/deletes are only honored by clients when ref.p === the envelope's pubkey
// (you can only edit/delete your OWN messages — the signature proves authorship).
export type MsgRef = { p: string; s: number } // pubkey (base64), per-sender seq
export type MessageMeta = {
  replyTo?: MsgRef // this message is a reply to ref
  edit?: MsgRef // this message replaces the text of ref (must be your own)
  del?: MsgRef // this message tombstones ref (must be your own)
  sys?: 'join' | 'leave' // a persisted presence line (no chat text); relay-blind
}

// ── Envelope ─────────────────────────────────────────────────────────────────
export type Envelope = {
  v: number
  room: string // opaque room id (hash)
  epoch: number // 0 in v1; MLS epoch in v2
  iv: string // base64, 12 bytes
  ciphertext: string // base64
  sender: string // pubkey fingerprint (opaque label)
  pubkey: string // base64 raw Ed25519 public key
  seq: number // monotonic per-sender
  sig: string // base64 Ed25519 signature
  ts: number // client timestamp
  id?: number // server-assigned row id
}

export type DecryptedMessage = {
  username: string
  text: string
  fingerprint: string
  pubkey: string
  seq: number
  ts: number
  id?: number
  mine: boolean
  replyTo?: MsgRef // set if this message is a reply
  editOf?: MsgRef // set if this message edits another (apply only if editOf.p === pubkey)
  deleteOf?: MsgRef // set if this message deletes another (apply only if deleteOf.p === pubkey)
  sys?: 'join' | 'leave' // set if this is a persisted presence line, not chat
}

// AAD binds the envelope header into the AEAD so ciphertext is non-transferable.
function buildAad(v: number, room: string, epoch: number, seq: number, pub: Uint8Array): Uint8Array {
  return concat(DOMAIN, new Uint8Array([v]), enc.encode(room), u64(epoch), u64(seq), pub)
}
// Bytes covered by the Ed25519 signature (binds ordering + room + body).
function buildSigned(
  v: number,
  room: string,
  epoch: number,
  seq: number,
  iv: Uint8Array,
  ct: Uint8Array,
): Uint8Array {
  return concat(DOMAIN, new Uint8Array([v]), enc.encode(room), u64(epoch), u64(seq), iv, ct)
}

/** Encrypt + sign a message. `room` is the opaque room id from deriveRoom().
 *  `meta` carries optional reply/edit/delete refs — all encrypted with the body. */
export async function sealMessage(
  key: CryptoKey,
  identity: Identity,
  room: string,
  seq: number,
  username: string,
  text: string,
  meta?: MessageMeta,
): Promise<Envelope> {
  const epoch = 0
  const v = PROTOCOL_VERSION
  const body: Record<string, unknown> = { u: username, m: text }
  if (meta?.replyTo) body.r = meta.replyTo
  if (meta?.edit) body.edit = meta.edit
  if (meta?.del) body.del = meta.del
  if (meta?.sys) body.sys = meta.sys
  const plain = enc.encode(JSON.stringify(body))
  const padded = pad(plain)
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const aad = buildAad(v, room, epoch, seq, identity.pub)
  const ctBuf = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: aad, tagLength: 128 },
    key,
    padded,
  )
  const ct = new Uint8Array(ctBuf)
  const sig = await signWithIdentity(identity, buildSigned(v, room, epoch, seq, iv, ct))
  return {
    v,
    room,
    epoch,
    iv: toB64(iv),
    ciphertext: toB64(ct),
    sender: identity.fingerprint,
    pubkey: identity.pubB64,
    seq,
    sig: toB64(sig),
    ts: Date.now(),
  }
}

/**
 * Verify signature, then decrypt. Throws on bad signature (forged sender) or
 * decrypt failure (wrong room password / tampering). The username is recovered
 * from inside the ciphertext.
 */
export async function openMessage(
  key: CryptoKey,
  env: Envelope,
  myPubB64: string,
): Promise<DecryptedMessage> {
  // Version gate FIRST: reject unsupported envelope versions before any crypto so
  // a mismatched/downgraded/forged `v` fails with a clear, distinct error rather
  // than an opaque AES-GCM/signature failure (which would mask a downgrade attempt
  // as ordinary corruption). `v` feeds buildAad/buildSigned, so this also prevents
  // an attacker steering AAD/signed-bytes construction via an out-of-range version.
  if (!SUPPORTED_VERSIONS.has(env.v)) {
    throw new Error(`unsupported protocol version: ${env.v}`)
  }

  const pub = fromB64(env.pubkey)
  const iv = fromB64(env.iv)
  const ct = fromB64(env.ciphertext)

  const sigOk = await ed.verifyAsync(
    fromB64(env.sig),
    buildSigned(env.v, env.room, env.epoch ?? 0, env.seq, iv, ct),
    pub,
  )
  if (!sigOk) throw new Error('signature verification failed')

  const aad = buildAad(env.v, env.room, env.epoch ?? 0, env.seq, pub)
  const padded = new Uint8Array(
    await crypto.subtle.decrypt({ name: 'AES-GCM', iv, additionalData: aad, tagLength: 128 }, key, ct),
  )
  const plain = unpad(padded)
  const obj = JSON.parse(dec.decode(plain)) as {
    u?: string
    m?: string
    r?: MsgRef
    edit?: MsgRef
    del?: MsgRef
    sys?: 'join' | 'leave'
  }

  const validRef = (x: unknown): MsgRef | undefined =>
    x && typeof x === 'object' && typeof (x as MsgRef).p === 'string' && typeof (x as MsgRef).s === 'number'
      ? { p: (x as MsgRef).p, s: (x as MsgRef).s }
      : undefined

  return {
    username: typeof obj.u === 'string' ? obj.u : '?',
    text: typeof obj.m === 'string' ? obj.m : '',
    fingerprint: await fingerprintOf(pub),
    pubkey: env.pubkey,
    seq: env.seq,
    ts: env.ts,
    id: env.id,
    mine: env.pubkey === myPubB64,
    replyTo: validRef(obj.r),
    editOf: validRef(obj.edit),
    deleteOf: validRef(obj.del),
    sys: obj.sys === 'join' || obj.sys === 'leave' ? obj.sys : undefined,
  }
}

// ── Presence ─────────────────────────────────────────────────────────────────
// A presence "hello" carries the username ENCRYPTED (relay can't read it) and is
// SIGNED so only the holder of the pubkey can announce for that identity. Leave
// events are server-attested (real socket close), so they need no client crypto.
export type PresenceEntry = {
  pid?: string
  pubkey: string
  sender: string
  iv: string
  ciphertext: string
  sig: string
}

export type PresenceMember = { pid?: string; pubkey: string; fingerprint: string; username: string }

function presenceAad(room: string, pub: Uint8Array): Uint8Array {
  return concat(DOMAIN, enc.encode('presence'), enc.encode(room), pub)
}
function presenceSigned(room: string, iv: Uint8Array, ct: Uint8Array): Uint8Array {
  return concat(DOMAIN, enc.encode('presence'), enc.encode(room), iv, ct)
}

/** Build a signed, encrypted presence announce for `room`. */
export async function sealPresence(
  key: CryptoKey,
  identity: Identity,
  room: string,
  username: string,
): Promise<PresenceEntry> {
  const padded = pad(enc.encode(JSON.stringify({ u: username })))
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const ctBuf = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: presenceAad(room, identity.pub), tagLength: 128 },
    key,
    padded,
  )
  const ct = new Uint8Array(ctBuf)
  const sig = await signWithIdentity(identity, presenceSigned(room, iv, ct))
  return {
    pubkey: identity.pubB64,
    sender: identity.fingerprint,
    iv: toB64(iv),
    ciphertext: toB64(ct),
    sig: toB64(sig),
  }
}

/** Verify + decrypt a presence entry into a roster member. Throws on failure. */
export async function openPresence(
  key: CryptoKey,
  room: string,
  entry: PresenceEntry,
): Promise<PresenceMember> {
  const pub = fromB64(entry.pubkey)
  const iv = fromB64(entry.iv)
  const ct = fromB64(entry.ciphertext)
  const sigOk = await ed.verifyAsync(fromB64(entry.sig), presenceSigned(room, iv, ct), pub)
  if (!sigOk) throw new Error('presence signature verification failed')
  const padded = new Uint8Array(
    await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv, additionalData: presenceAad(room, pub), tagLength: 128 },
      key,
      ct,
    ),
  )
  const obj = JSON.parse(dec.decode(unpad(padded))) as { u?: string }
  return {
    pid: entry.pid,
    pubkey: entry.pubkey,
    fingerprint: await fingerprintOf(pub),
    username: typeof obj.u === 'string' ? obj.u : '?',
  }
}
