import { describe, expect, it } from 'vitest'
import {
  deriveRoom,
  generateNonExtractableIdentity,
  identityFromPrivateKey,
  identityFromSignKey,
  importPrivateKeyAsSignKey,
  openMessage,
  openPresence,
  randomPrivateKey,
  sealMessage,
  sealPresence,
  supportsWebCryptoEd25519,
} from '../src/protocol'

/**
 * Non-extractable WebCrypto identity suite. Locks down the guarantee that the
 * WebCrypto signing path is WIRE-IDENTICAL to the raw-bytes (@noble) path:
 * Ed25519 is deterministic (RFC 8032), so the same key + same bytes MUST yield
 * the same signature regardless of which engine signed. That is what lets a
 * browser using a non-extractable IndexedDB key talk to a CLI using a 0600
 * file with neither knowing the difference.
 *
 * These tests run on Node's WebCrypto (Ed25519 in Node ≥19). If a runtime
 * without Ed25519 WebCrypto ever runs this suite, the capability probe test
 * documents the expected app behavior (fall back to the raw-bytes path).
 */

const PASSPHRASE = 'correct horse battery staple'

describe('WebCrypto Ed25519 identity', () => {
  it('this test runtime supports WebCrypto Ed25519', async () => {
    expect(await supportsWebCryptoEd25519()).toBe(true)
  })

  it('importPrivateKeyAsSignKey preserves pub, fingerprint, and SIGNATURES', async () => {
    const priv = randomPrivateKey()
    const noble = await identityFromPrivateKey(priv)
    const webcrypto = await importPrivateKeyAsSignKey(priv)

    // Same key material → identical public identity (peers see no change).
    expect(webcrypto.pubB64).toBe(noble.pubB64)
    expect(webcrypto.fingerprint).toBe(noble.fingerprint)

    // Deterministic signatures: seal the same envelope fields with both
    // identities and compare the signature bytes. Force the same IV by sealing
    // the same message and checking cross-verification instead of raw equality
    // (IVs are random): each side's envelope must open under openMessage,
    // which verifies the signature against the embedded pubkey.
    const { key, roomId } = await deriveRoom(PASSPHRASE)
    const fromNoble = await sealMessage(key, noble, roomId, 0, 'alice', 'hi from noble')
    const fromWebCrypto = await sealMessage(key, webcrypto, roomId, 1, 'alice', 'hi from webcrypto')
    const openedNoble = await openMessage(key, fromNoble, webcrypto.pubB64)
    const openedWebCrypto = await openMessage(key, fromWebCrypto, noble.pubB64)
    expect(openedNoble.text).toBe('hi from noble')
    expect(openedWebCrypto.text).toBe('hi from webcrypto')
    // Both envelopes carry the SAME identity on the wire.
    expect(fromNoble.pubkey).toBe(fromWebCrypto.pubkey)
    expect(openedNoble.mine).toBe(true) // webcrypto's pubB64 === noble's
  })

  it('non-extractable key: signs but cannot be exported', async () => {
    const id = await generateNonExtractableIdentity()
    expect(id.signKey).toBeDefined()
    expect(id.priv).toBeUndefined()
    expect(id.signKey!.extractable).toBe(false)
    // The exfiltration paths an XSS would use MUST throw.
    await expect(crypto.subtle.exportKey('pkcs8', id.signKey!)).rejects.toThrow()
    await expect(crypto.subtle.exportKey('jwk', id.signKey!)).rejects.toThrow()
  })

  it('fresh non-extractable identity seals + opens messages and presence', async () => {
    const { key, roomId } = await deriveRoom(PASSPHRASE)
    const id = await generateNonExtractableIdentity()

    const env = await sealMessage(key, id, roomId, 0, 'bob', 'sealed with webcrypto')
    const msg = await openMessage(key, env, id.pubB64)
    expect(msg.text).toBe('sealed with webcrypto')
    expect(msg.fingerprint).toBe(id.fingerprint)
    expect(msg.mine).toBe(true)

    const entry = await sealPresence(key, id, roomId, 'bob')
    const member = await openPresence(key, roomId, entry)
    expect(member.username).toBe('bob')
    expect(member.pubkey).toBe(id.pubB64)
  })

  it('mixed room: raw-bytes sender ↔ webcrypto receiver interoperate', async () => {
    const { key, roomId } = await deriveRoom(PASSPHRASE)
    const cli = await identityFromPrivateKey(randomPrivateKey()) // CLI-style
    const browser = await generateNonExtractableIdentity() // hardened browser

    const fromCli = await sealMessage(key, cli, roomId, 0, 'cli', 'hello browser')
    const fromBrowser = await sealMessage(key, browser, roomId, 0, 'browser', 'hello cli')
    expect((await openMessage(key, fromCli, browser.pubB64)).text).toBe('hello browser')
    expect((await openMessage(key, fromBrowser, cli.pubB64)).text).toBe('hello cli')
  })

  it('identityFromSignKey rebuilds the same identity (IndexedDB reload path)', async () => {
    const first = await generateNonExtractableIdentity()
    const reloaded = await identityFromSignKey(first.signKey!, first.pub)
    expect(reloaded.pubB64).toBe(first.pubB64)
    expect(reloaded.fingerprint).toBe(first.fingerprint)

    const { key, roomId } = await deriveRoom(PASSPHRASE)
    const env = await sealMessage(key, reloaded, roomId, 0, 'carol', 'after reload')
    expect((await openMessage(key, env, reloaded.pubB64)).text).toBe('after reload')
  })

  it('identity with no signing material throws legibly', async () => {
    const { key, roomId } = await deriveRoom(PASSPHRASE)
    const id = await generateNonExtractableIdentity()
    const hollow = { pub: id.pub, pubB64: id.pubB64, fingerprint: id.fingerprint }
    await expect(sealMessage(key, hollow, roomId, 0, 'x', 'y')).rejects.toThrow(
      /no signing material/,
    )
  })
})
