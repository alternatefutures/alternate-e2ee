import { describe, expect, it } from 'vitest'
import WebSocket from 'ws'
import { ChatClient, deriveIdentityFromSeed } from '../src/node-client'
import { deriveRoom, identityFromPrivateKey, openPresence, type PresenceEntry } from '../src/protocol'

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

  it('sends an ephemeral typing frame peers can open, and nothing without an open socket', async () => {
    const identity = await deriveIdentityFromSeed(SEED, 'loco')
    const client = new ChatClient({
      wsUrl: 'wss://relay.invalid/ws',
      password: 'acid acorn acre acid acorn acre',
      username: 'loco',
      identity,
    })
    expect(await client.typing(true)).toBe(false)
    await client.ensureRoom()
    const sent: string[] = []
    ;(client as unknown as { ws: unknown }).ws = {
      readyState: WebSocket.OPEN,
      send: (frame: string) => sent.push(frame),
    }
    expect(await client.typing(true)).toBe(true)
    expect(await client.typing(false)).toBe(true)
    expect(sent).toHaveLength(2)
    const frame = JSON.parse(sent[0]) as Record<string, unknown>
    expect(frame).toMatchObject({ t: 'typing', room: client.roomId, active: true, pubkey: identity.pubB64 })
    expect(JSON.parse(sent[1])).toMatchObject({ t: 'typing', active: false })
    // The relay forwards the opaque entry; a member with the room key recovers who.
    const room = await deriveRoom('acid acorn acre acid acorn acre')
    const who = await openPresence(room.key, client.roomId, frame as unknown as PresenceEntry)
    expect(who.username).toBe('loco')
    expect(JSON.stringify(frame)).not.toContain('loco')
  })
})
