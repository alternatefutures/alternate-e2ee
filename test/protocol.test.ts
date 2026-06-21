import { describe, expect, it } from 'vitest'
import {
  ROOM_ID_RE,
  ROOM_SALT,
  deriveRaw,
  deriveRoom,
  deriveRoomBytes,
  identityFromPrivateKey,
  openMessage,
  randomPrivateKey,
  sealMessage,
} from '../src/protocol'

// Golden interop vector — DO NOT CHANGE without bumping PROTOCOL_VERSION.
// The default derivation (salt = ROOM_SALT 'alt-chat/room/v2', no NFKC) MUST stay
// byte-identical to alt-chat v2, or existing chat/CLI rooms break. Computed from
// the shared protocol; a drift here means interop is broken.
const GOLDEN_PASSPHRASE = 'correct horse battery staple'
const GOLDEN_ROOM_ID = 'UfhmLK8Ogmpvx3zVkpugLRI57fjpgtFVoTpoI4kz7Jo'

describe('room derivation', () => {
  it('is deterministic', async () => {
    const a = await deriveRoomBytes(GOLDEN_PASSPHRASE)
    const b = await deriveRoomBytes(GOLDEN_PASSPHRASE)
    expect(a.roomId).toBe(b.roomId)
    expect([...a.keyBytes]).toEqual([...b.keyBytes])
    expect(ROOM_ID_RE.test(a.roomId)).toBe(true)
  })

  it('different passphrase → different room', async () => {
    const a = await deriveRoomBytes('passphrase one')
    const b = await deriveRoomBytes('passphrase two')
    expect(a.roomId).not.toBe(b.roomId)
  })

  it('salt domain-separates (same passphrase, different app)', async () => {
    const chat = await deriveRoomBytes('shared phrase', { salt: ROOM_SALT })
    const video = await deriveRoomBytes('shared phrase', { salt: 'alternate-connect/meet/v1' })
    expect(chat.roomId).not.toBe(video.roomId)
    expect([...chat.keyBytes]).not.toEqual([...video.keyBytes])
  })

  it('NFKC normalization changes the output only when enabled', async () => {
    // 'é' composed (U+00E9) vs decomposed (e + U+0301)
    const composed = 'cafeé'
    const decomposed = 'cafeé'
    const offA = await deriveRoomBytes(composed, { normalize: false })
    const offB = await deriveRoomBytes(decomposed, { normalize: false })
    expect(offA.roomId).not.toBe(offB.roomId) // raw bytes differ
    const onA = await deriveRoomBytes(composed, { normalize: true })
    const onB = await deriveRoomBytes(decomposed, { normalize: true })
    expect(onA.roomId).toBe(onB.roomId) // NFKC folds them together
  })

  it('deriveRoom (CryptoKey) and deriveRoomBytes agree on roomId', async () => {
    const room = await deriveRoom(GOLDEN_PASSPHRASE)
    const bytes = await deriveRoomBytes(GOLDEN_PASSPHRASE)
    expect(room.roomId).toBe(bytes.roomId)
    expect(room.key).toBeInstanceOf(CryptoKey)
  })

  it('matches the golden interop vector', async () => {
    const { roomId } = await deriveRoomBytes(GOLDEN_PASSPHRASE)
    expect(roomId).toBe(GOLDEN_ROOM_ID)
  })

  it('deriveRaw returns 64 bytes split key‖roomId', async () => {
    const raw = await deriveRaw(GOLDEN_PASSPHRASE)
    expect(raw.length).toBe(64)
  })
})

describe('message seal/open round-trip', () => {
  it('encrypts, signs, then verifies + decrypts', async () => {
    const { key, roomId } = await deriveRoom('a-strong-shared-passphrase')
    const id = await identityFromPrivateKey(randomPrivateKey())
    const env = await sealMessage(key, id, roomId, 1, 'alice', 'hello world', {
      replyTo: { p: 'somepub', s: 3 },
    })
    const opened = await openMessage(key, env, id.pubB64)
    expect(opened.text).toBe('hello world')
    expect(opened.username).toBe('alice')
    expect(opened.mine).toBe(true)
    expect(opened.replyTo).toEqual({ p: 'somepub', s: 3 })
  })

  it('a wrong-key room cannot open the message', async () => {
    const sender = await deriveRoom('the real passphrase')
    const wrong = await deriveRoom('a different passphrase')
    const id = await identityFromPrivateKey(randomPrivateKey())
    const env = await sealMessage(sender.key, id, sender.roomId, 1, 'bob', 'secret', undefined)
    await expect(openMessage(wrong.key, env, id.pubB64)).rejects.toThrow()
  })
})
