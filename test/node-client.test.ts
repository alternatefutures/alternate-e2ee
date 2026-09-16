import { describe, expect, it } from 'vitest'
import { ChatClient, deriveIdentityFromSeed } from '../src/node-client'
import { identityFromPrivateKey } from '../src/protocol'

const SEED = 'ab'.repeat(32)

describe('deriveIdentityFromSeed', () => {
  it('is deterministic per (seed, label) and distinct across labels and seeds', async () => {
    const a1 = await deriveIdentityFromSeed(SEED, 'researcher')
    const a2 = await deriveIdentityFromSeed(SEED, 'researcher')
    const b = await deriveIdentityFromSeed(SEED, 'reviewer')
    const c = await deriveIdentityFromSeed('cd'.repeat(32), 'researcher')
    expect(a1.fingerprint).toBe(a2.fingerprint)
    expect(a1.pubB64).toBe(a2.pubB64)
    expect(a1.fingerprint).not.toBe(b.fingerprint)
    expect(a1.fingerprint).not.toBe(c.fingerprint)
    // A real 32-byte private key: the protocol rebuilds the same public key.
    const rebuilt = await identityFromPrivateKey(a1.priv as Uint8Array)
    expect(rebuilt.pubB64).toBe(a1.pubB64)
  })

  it('refuses a malformed seed or label before deriving', async () => {
    await expect(deriveIdentityFromSeed('zz', 'x')).rejects.toThrow(
      'participant_seed_invalid',
    )
    await expect(deriveIdentityFromSeed(SEED, '')).rejects.toThrow(
      'participant_label_invalid',
    )
  })
})

describe('ChatClient (no network)', () => {
  it('derives the room label from the passphrase alone before connecting', async () => {
    const identity = await deriveIdentityFromSeed(SEED, 'researcher')
    const client = new ChatClient({
      wsUrl: 'wss://relay.invalid/ws',
      password: 'acid acorn acre acid acorn acre',
      username: 'researcher',
      identity,
    })
    expect(client.roomLabel).toBe('')
    await client.ensureRoom()
    expect(client.roomId).toMatch(/^[A-Za-z0-9_-]{20,}$/)
    expect(client.roomLabel).toMatch(/^[a-z]+-[a-z]+$/)
    expect(client.myPubkey).toBe(identity.pubB64)
    expect(client.members).toEqual([])
  })
})
