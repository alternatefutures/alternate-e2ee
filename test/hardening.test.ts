import { describe, expect, it } from 'vitest'
import {
  APP_SALTS,
  PROTOCOL_VERSION,
  ROOM_SALT,
  SUPPORTED_VERSIONS,
  deriveRaw,
  deriveRoom,
  identityFromPrivateKey,
  openMessage,
  randomPrivateKey,
  sealMessage,
  toB64,
} from '../src/protocol'

/**
 * Hardening + known-answer suite. These lock down the protocol INVARIANTS that
 * keep the E2EE guarantees from silently regressing:
 *   - the KDF output is byte-pinned (any accidental param change is caught here),
 *   - the envelope version is gated before any crypto runs (downgrade legibility),
 *   - the AAD + signed-bytes bind {version, room, epoch, seq} (no cross-context
 *     replay, no field tampering),
 *   - fresh IV per message (no AES-GCM nonce reuse),
 *   - per-app salts are pairwise distinct (no cross-app key/room collision).
 * Changing any *expected value* here means a wire-breaking change → bump
 * PROTOCOL_VERSION + the package version together (see protocol.ts header).
 */

// ── Known-answer vector: pins the full Argon2id output, both halves ───────────
// deriveRaw = 64 bytes: [0..32) AES-256-GCM key ‖ [32..64) opaque room id.
// Computed from the shipped protocol; a drift means the KDF params or salt moved
// and every existing chat/CLI/video room would break.
const KAT_PASSPHRASE = 'correct horse battery staple'
const KAT_RAW64_HEX =
  'f63d375091ef2165e252ea605a8fc4fcc3d889d6f7dfdbe395f57944c90c5616' +
  '51f8662caf0e826a6fc77cd5929ba02d1239edf8e982d155a13a68238933ec9a'

const toHex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('')

describe('KDF known-answer vector', () => {
  it('deriveRaw is byte-identical to the pinned vector', async () => {
    const raw = await deriveRaw(KAT_PASSPHRASE)
    expect(raw.length).toBe(64)
    expect(toHex(raw)).toBe(KAT_RAW64_HEX)
  })

  it('the AES key half and room-id half are independent (differ)', async () => {
    const raw = await deriveRaw(KAT_PASSPHRASE)
    expect(toHex(raw.slice(0, 32))).not.toBe(toHex(raw.slice(32, 64)))
  })
})

describe('protocol invariants', () => {
  it('per-app salts are pairwise distinct', () => {
    const values = Object.values(APP_SALTS)
    expect(new Set(values).size).toBe(values.length)
  })

  it('chat salt is the canonical ROOM_SALT; connect salt is the meet salt', () => {
    expect(APP_SALTS.chat).toBe(ROOM_SALT)
    expect(APP_SALTS.chat).toBe('alt-chat/room/v2')
    expect(APP_SALTS.connect).toBe('alternate-connect/meet/v1')
  })

  it('SUPPORTED_VERSIONS contains exactly the current PROTOCOL_VERSION', () => {
    expect(SUPPORTED_VERSIONS.has(PROTOCOL_VERSION)).toBe(true)
    expect([...SUPPORTED_VERSIONS]).toEqual([PROTOCOL_VERSION])
  })
})

describe('envelope version gate (downgrade legibility)', () => {
  it('rejects every unsupported version with a DISTINCT version error, before crypto', async () => {
    const { key, roomId } = await deriveRoom('gate-test-passphrase')
    const id = await identityFromPrivateKey(randomPrivateKey())
    const env = await sealMessage(key, id, roomId, 1, 'alice', 'hi', undefined)
    for (const v of [0, 1, 3, 999, -1, Number.NaN]) {
      await expect(openMessage(key, { ...env, v }, id.pubB64)).rejects.toThrow(
        /unsupported protocol version/,
      )
    }
  })

  it('accepts the current version untouched (round-trip still works)', async () => {
    const { key, roomId } = await deriveRoom('gate-test-passphrase')
    const id = await identityFromPrivateKey(randomPrivateKey())
    const env = await sealMessage(key, id, roomId, 7, 'alice', 'hello', undefined)
    expect(env.v).toBe(PROTOCOL_VERSION)
    const opened = await openMessage(key, env, id.pubB64)
    expect(opened.text).toBe('hello')
  })
})

describe('AAD + signature binding (anti-replay / anti-tamper)', () => {
  it('tampering the room id fails verification', async () => {
    const { key, roomId } = await deriveRoom('bind-test')
    const id = await identityFromPrivateKey(randomPrivateKey())
    const env = await sealMessage(key, id, roomId, 1, 'a', 'm', undefined)
    await expect(openMessage(key, { ...env, room: `${roomId}x`.slice(1) }, id.pubB64)).rejects.toThrow()
  })

  it('tampering the seq fails verification', async () => {
    const { key, roomId } = await deriveRoom('bind-test')
    const id = await identityFromPrivateKey(randomPrivateKey())
    const env = await sealMessage(key, id, roomId, 1, 'a', 'm', undefined)
    await expect(openMessage(key, { ...env, seq: env.seq + 1 }, id.pubB64)).rejects.toThrow()
  })

  it('tampering the epoch fails verification', async () => {
    const { key, roomId } = await deriveRoom('bind-test')
    const id = await identityFromPrivateKey(randomPrivateKey())
    const env = await sealMessage(key, id, roomId, 1, 'a', 'm', undefined)
    await expect(openMessage(key, { ...env, epoch: (env.epoch ?? 0) + 1 }, id.pubB64)).rejects.toThrow()
  })

  it('a flipped signature byte fails verification', async () => {
    const { key, roomId } = await deriveRoom('bind-test')
    const id = await identityFromPrivateKey(randomPrivateKey())
    const env = await sealMessage(key, id, roomId, 1, 'a', 'm', undefined)
    const sig = Uint8Array.from(atob(env.sig), (c) => c.charCodeAt(0))
    sig[0] ^= 0xff
    await expect(openMessage(key, { ...env, sig: toB64(sig) }, id.pubB64)).rejects.toThrow()
  })

  it('ciphertext cannot be replayed into a different room key', async () => {
    const roomA = await deriveRoom('room-A-passphrase')
    const roomB = await deriveRoom('room-B-passphrase')
    const id = await identityFromPrivateKey(randomPrivateKey())
    const env = await sealMessage(roomA.key, id, roomA.roomId, 1, 'a', 'secret', undefined)
    // Same envelope (incl. its A room-id), but decrypt attempted with B's key.
    await expect(openMessage(roomB.key, env, id.pubB64)).rejects.toThrow()
  })
})

describe('nonce uniqueness (no AES-GCM IV reuse)', () => {
  it('two seals of identical plaintext use different IVs', async () => {
    const { key, roomId } = await deriveRoom('iv-test')
    const id = await identityFromPrivateKey(randomPrivateKey())
    const e1 = await sealMessage(key, id, roomId, 1, 'a', 'same text', undefined)
    const e2 = await sealMessage(key, id, roomId, 2, 'a', 'same text', undefined)
    expect(e1.iv).not.toBe(e2.iv)
    expect(e1.ciphertext).not.toBe(e2.ciphertext)
  })
})
