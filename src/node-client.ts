/**
 * `@alternatefutures/e2ee/node-client`: the Node chat client for alt-chat rooms
 * (Ed25519 identity, room derived from the passphrase alone, presence,
 * history replay, edits/deletes, reconnect). Moved here from
 * `alternate-clouds-cli/src/commands/chat/client.ts` on 2026-09-16 so the CLI,
 * the swarm bridge (one room member per agent) and any other Node consumer
 * share ONE implementation; the CLI file is now a re-export shim.
 *
 * Node 18: import `@alternatefutures/e2ee/node` first (WebCrypto global shim).
 * Requires the `ws` package (peer of this entry).
 */
/**
 * ChatClient — the headless, Node-side equivalent of the browser's `useChat`.
 *
 * It owns the WebSocket lifecycle and the crypto pipeline against a blind
 * alt-chat relay: derive the room key + opaque room id, subscribe, announce
 * presence (encrypted + signed), then verify + decrypt every envelope in arrival
 * order while enforcing a monotonic per-sender `seq` (drops replays / reorders).
 * The relay only ever sees ciphertext + opaque presence blobs.
 *
 * It's transport for THREE front-ends: an interactive TUI (`acc chat join`) and
 * two one-shot, no-TTY commands for agents (`acc chat send`, `acc chat read`).
 * Everything is surfaced as events so each front-end renders it differently.
 */

import { EventEmitter } from 'node:events';

import WebSocket from 'ws';

import {
  type DecryptedMessage,
  type Envelope,
  type Identity,
  type MessageMeta,
  type MsgRef,
  type PresenceEntry,
  type PresenceMember,
  deriveRoom,
  identityFromPrivateKey,
  openMessage,
  openPresence,
  sealMessage,
  sealPresence,
} from './protocol';
import { roomLabel } from './wordlist';

export type ConnStatus =
  | 'connecting'
  | 'connected'
  | 'reconnecting'
  | 'closed'
  | 'error';

/** A roster member. `spoof` is true when this username is claimed by more than
 *  one distinct online pubkey (possible impersonation) — mirrors the web. */
export type ChatMember = PresenceMember & { pid: string; spoof: boolean };

/** A settled chat message: the decrypted body plus the edit/delete state the
 *  client has applied for it (mirrors the web's ChatMessage). */
export type ChatMessage = DecryptedMessage & {
  key: string; // `${pubkey}:${seq}`
  edited?: boolean;
  deleted?: boolean;
};

/** A persisted presence line (join/left) recovered from the encrypted transcript. */
export type ChatSystemEvent = {
  type: 'join' | 'leave';
  username: string;
  fingerprint: string;
  pubkey: string;
  ts: number;
  key: string;
};

export type ChatClientOptions = {
  wsUrl: string;
  password: string;
  username: string;
  identity: Identity;
  /** Reconnect on unexpected socket close (default: false — one-shot safe). */
  autoReconnect?: boolean;
  /** Give up (and emit `close`) after this many consecutive failed reconnects.
   *  The counter resets on every successful connection (default: 5). */
  maxReconnectAttempts?: number;
  /** Abort the initial connect after this many ms (default: 20000). */
  connectTimeoutMs?: number;
  /** Persist an encrypted "joined"/"left" line in the transcript (like the web).
   *  ON for long-lived sessions (`join`, `agent`); OFF for one-shot `send`/`read`
   *  so an agent polling a room doesn't spam join/left pairs into history. */
  announcePresence?: boolean;
  /** Mint a single-use join ticket to put in the `sub` frame — set only for the
   *  AlternateFutures-hosted relays (see `ticket.ts`). Called on EVERY connect
   *  AND reconnect, because a ticket is burned by the first use. Undefined for
   *  self-hosted relays, which stay anonymous. */
  ticketProvider?: () => Promise<string>;
};

/**
 * Events emitted:
 *   status(s)            — connection status transitions
 *   message(msg)         — a new decrypted chat message (history replay AND live)
 *   edit(msg)            — an already-emitted message's text changed (author edit)
 *   delete(msg)          — an already-emitted message was tombstoned (author delete)
 *   system(ev)           — a persisted presence line (join/left) from the transcript
 *   creator(pubkey)      — the room creator (author of the lowest-id message) is known/changed
 *   ready()              — initial history replay finished decrypting
 *   join(member)         — someone announced presence
 *   leave(member)        — someone's socket closed (server-attested)
 *   roster(members)      — full current roster (deduped by pubkey, after our hello)
 *   undecryptable(n)     — running count of envelopes we couldn't open
 *   relayError(message)  — the relay rejected a frame
 *   close()              — socket closed and we will not reconnect
 */
export class ChatClient extends EventEmitter {
  private ws: WebSocket | null = null;
  private readonly opts: Required<
    Pick<
      ChatClientOptions,
      'autoReconnect' | 'connectTimeoutMs' | 'maxReconnectAttempts'
    >
  > &
    ChatClientOptions;

  private key: CryptoKey | null = null;
  private rid = '';
  private mySeq = 0;
  // Exact (pubkey:seq) dedupe is the ONLY replay guard — we deliberately do NOT
  // reject "older" seqs (an edit/delete refs an older seq, and a reorder across a
  // reconnect history-replay must still be accepted). Mirrors the web's useChat.
  private readonly seenKeys = new Set<string>();
  private readonly roster = new Map<string, PresenceMember & { pid: string }>();
  private queue: Promise<void> = Promise.resolve();

  // Settled message index — applies edits/deletes in place (mirrors useChat).
  private readonly msgList: ChatMessage[] = [];
  private readonly byKey = new Map<string, ChatMessage>();
  // Edits can arrive before their target; buffer (bounded). Deletes are terminal.
  private static readonly PENDING_CAP = 2000;
  private readonly pendingEdits = new Map<string, string>();
  private readonly deletedKeys = new Set<string>();

  // Room creator = author of the lowest relay-assigned id (signed → authenticated).
  private creatorPub = '';
  private creatorMinId = Number.POSITIVE_INFINITY;

  private undecryptableCount = 0;
  private historyDone = false;
  private announced = false;
  // `hello` is deferred until the relay's `history` frame acks the subscription
  // (the sub is ASYNC on a ticket-gated relay — it round-trips to the api).
  // Reset per connection so every reconnect re-announces presence.
  private helloSent = false;
  private pendingSends: { text: string; replyTo?: MsgRef }[] = [];
  private reconnectAttempts = 0;
  private alive = false;
  private intentionalClose = false;
  private pingTimer: ReturnType<typeof setInterval> | null = null;
  private retryTimer: ReturnType<typeof setTimeout> | null = null;
  private connectTimer: ReturnType<typeof setTimeout> | null = null;

  constructor(options: ChatClientOptions) {
    super();
    this.opts = {
      autoReconnect: false,
      connectTimeoutMs: 20_000,
      maxReconnectAttempts: 5,
      ...options,
    };
  }

  /** Current reconnect attempt and the configured ceiling (for UI). */
  get reconnect(): { attempt: number; max: number } {
    return {
      attempt: this.reconnectAttempts,
      max: this.opts.maxReconnectAttempts,
    };
  }

  /** The live roster, deduped by pubkey (one entry per identity even if a user is
   *  mid-reconnect or multi-connected) and flagged for username spoofing. */
  get members(): ChatMember[] {
    const all = [...this.roster.values()];
    // A username claimed by >1 distinct online pubkey = possible impersonation.
    const pubsByName = new Map<string, Set<string>>();
    for (const m of all) {
      let set = pubsByName.get(m.username);
      if (!set) {
        set = new Set();
        pubsByName.set(m.username, set);
      }
      set.add(m.pubkey);
    }
    const seen = new Set<string>();
    const out: ChatMember[] = [];
    for (const m of all) {
      if (seen.has(m.pubkey)) continue;
      seen.add(m.pubkey);
      out.push({ ...m, spoof: (pubsByName.get(m.username)?.size ?? 0) > 1 });
    }
    return out;
  }

  get myFingerprint(): string {
    return this.opts.identity.fingerprint;
  }

  /** Our own raw Ed25519 public key (base64) — used to detect self-replies/mentions. */
  get myPubkey(): string {
    return this.opts.identity.pubB64;
  }

  /** The room creator's pubkey (author of the lowest-id message), or '' if unknown. */
  get creatorPubkey(): string {
    return this.creatorPub;
  }

  /** The settled message list with edits/deletes already applied (for snapshots). */
  get messages(): ChatMessage[] {
    return this.msgList;
  }

  /** The opaque wire room id (set once {@link ensureRoom} has run). */
  get roomId(): string {
    return this.rid;
  }

  /** A friendly, deterministic 2-word label for the room, derived from the room
   *  id — the same label every client (web + CLI) shows for this passphrase.
   *  Empty until {@link ensureRoom}/{@link start} has derived the room. */
  get roomLabel(): string {
    return this.rid ? roomLabel(this.rid) : '';
  }

  /** Derive the room key + opaque room id from the passphrase (idempotent). Lets
   *  a caller learn {@link roomLabel} before connecting — `start()` calls it too. */
  async ensureRoom(): Promise<void> {
    if (this.key) return;
    // v2: the room derives from the passphrase ALONE; there is no room name.
    const room = await deriveRoom(this.opts.password);
    this.key = room.key;
    this.rid = room.roomId;
  }

  /** Derive the room (once) and open the socket. Resolves when the key is ready
   *  — connection progress is reported through events, not this promise. */
  async start(): Promise<void> {
    await this.ensureRoom();
    this.alive = true;
    this.intentionalClose = false;
    this.reconnectAttempts = 0;
    this.connect();
  }

  private connect(): void {
    if (!this.alive) return;
    this.emit('status', 'connecting' as ConnStatus);
    this.helloSent = false;

    const sock = new WebSocket(this.opts.wsUrl, { perMessageDeflate: false });
    this.ws = sock;

    this.connectTimer = setTimeout(() => {
      if (sock.readyState !== WebSocket.OPEN) {
        this.emit('relayError', `connection timed out (${this.opts.wsUrl})`);
        sock.terminate();
      }
    }, this.opts.connectTimeoutMs);

    sock.on('open', () => {
      if (this.connectTimer) clearTimeout(this.connectTimer);
      if (!this.alive) return;
      this.reconnectAttempts = 0; // a good connection resets the retry budget
      this.emit('status', 'connected' as ConnStatus);
      void this.subscribe(sock);
      if (this.pingTimer) clearInterval(this.pingTimer);
      this.pingTimer = setInterval(() => {
        if (sock.readyState === WebSocket.OPEN) {
          sock.send(JSON.stringify({ t: 'ping' }));
        }
      }, 30_000);
    });

    sock.on('message', (data: WebSocket.RawData) => {
      let frame: Record<string, unknown>;
      try {
        frame = JSON.parse(data.toString());
      } catch {
        return;
      }
      this.handleFrame(frame);
    });

    sock.on('close', () => {
      if (this.pingTimer) clearInterval(this.pingTimer);
      if (this.connectTimer) clearTimeout(this.connectTimer);
      if (!this.alive || this.intentionalClose) {
        this.emit('status', 'closed' as ConnStatus);
        this.emit('close');
        return;
      }
      if (
        this.opts.autoReconnect &&
        this.reconnectAttempts < this.opts.maxReconnectAttempts
      ) {
        this.reconnectAttempts += 1;
        this.emit('status', 'reconnecting' as ConnStatus);
        // Exponential backoff (1.5s, 3s, 6s, …) capped at 15s — don't hammer a
        // relay that's down, and don't spin forever.
        const delay = Math.min(
          1500 * 2 ** (this.reconnectAttempts - 1),
          15_000,
        );
        this.retryTimer = setTimeout(() => this.connect(), delay);
      } else {
        // Either reconnect is off (one-shot), or we exhausted the retry budget.
        this.alive = false;
        if (this.opts.autoReconnect) {
          this.emit(
            'relayError',
            `gave up after ${this.opts.maxReconnectAttempts} reconnect attempts`,
          );
        }
        this.emit('status', 'closed' as ConnStatus);
        this.emit('close');
      }
    });

    sock.on('error', (err: Error) => {
      this.emit('relayError', err.message);
      sock.close();
    });
  }

  /**
   * Send the `sub` frame, minting a single-use join ticket first when this relay
   * requires one (AF_CHAT_AUTH_PLAN.md §2.5).
   *
   * On a ticket-gated relay the server's sub handling is ASYNC (it round-trips
   * to the platform api to redeem the ticket), so `hello` is NOT sent here — it
   * waits for the `history` frame, which is the subscription ack. That defer is
   * harmless against an un-gated relay too: history still arrives right after
   * sub.
   */
  private async subscribe(sock: WebSocket): Promise<void> {
    let ticket: string | undefined;
    if (this.opts.ticketProvider) {
      try {
        ticket = await this.opts.ticketProvider();
      } catch (error) {
        // Not logged in / dead credential — deterministic, so reconnecting
        // cannot fix it. Surface it and stop.
        this.alive = false;
        this.emit(
          'relayError',
          error instanceof Error ? error.message : String(error),
        );
        sock.close();
        return;
      }
    }
    if (!this.alive || sock.readyState !== WebSocket.OPEN) return;
    sock.send(
      JSON.stringify({
        t: 'sub',
        room: this.rid,
        ...(ticket ? { ticket } : {}),
      }),
    );
  }

  /** Announce presence (encrypted + signed username) — once per connection. */
  private sendHello(sock: WebSocket): void {
    if (this.helloSent || !this.key) return;
    this.helloSent = true;
    sealPresence(this.key, this.opts.identity, this.rid, this.opts.username)
      .then((entry) => {
        if (sock.readyState === WebSocket.OPEN) {
          sock.send(JSON.stringify({ t: 'hello', room: this.rid, ...entry }));
        }
      })
      .catch(() => {
        // A failed presence announcement must not tear down the session.
      });
  }

  private handleFrame(frame: Record<string, unknown>): void {
    switch (frame.t) {
      case 'history':
        // The subscription is confirmed — now it's safe to announce presence.
        if (this.ws) this.sendHello(this.ws);
        if (Array.isArray(frame.msgs)) {
          for (const env of frame.msgs as Envelope[]) this.handleEnvelope(env);
        }
        // Sentinel: fires after every history envelope above has decrypted,
        // because the queue is strictly sequential. Only now is `mySeq` caught
        // up to our own past messages, so it's safe to flush queued sends.
        this.enqueue(async () => {
          if (!this.historyDone) {
            this.historyDone = true;
            this.emit('ready');
            // Persist a one-time encrypted "joined" line (long-lived sessions only)
            // now that mySeq is caught up to our own history — avoids a seq clash.
            if (this.opts.announcePresence && !this.announced) {
              this.announced = true;
              await this.sendSys('join');
            }
            const pending = this.pendingSends.splice(0);
            for (const p of pending) void this.doSend(p.text, p.replyTo);
          }
        });
        break;
      case 'msg':
        if (frame.env) this.handleEnvelope(frame.env as Envelope);
        break;
      case 'roster':
        if (Array.isArray(frame.members)) {
          this.handleRoster(frame.members as PresenceEntry[]);
        }
        break;
      case 'join':
        if (frame.member) this.handleJoin(frame.member as PresenceEntry);
        break;
      case 'leave':
        if (typeof frame.pid === 'string') this.handleLeave(frame.pid);
        break;
      case 'err': {
        const message = String(frame.message ?? 'relay error');
        // A login-gated relay refusing us is deterministic: 'auth required'
        // means we sent no ticket, 'ticket rejected' means the api refused the
        // one we sent (usually the CLI pointed at a DIFFERENT api than the relay
        // redeems against). Neither is fixed by reconnecting, so don't spend the
        // 5-attempt budget on it.
        if (message === 'auth required' || message === 'ticket rejected') {
          this.alive = false;
          this.emit('relayError', message);
          this.ws?.close();
          return;
        }
        this.emit('relayError', message);
        break;
      }
      default:
        // welcome / pong / unknown — ignore.
        break;
    }
  }

  /** Serialize decryption so emitted order matches arrival order. */
  private enqueue(fn: () => Promise<void>): void {
    this.queue = this.queue.then(fn).catch(() => {
      // Frame-specific failures are isolated so subsequent ordered frames run.
    });
  }

  private handleEnvelope(env: Envelope): void {
    this.enqueue(async () => {
      const key = this.key;
      if (!key) return;

      const dedupeKey = `${env.pubkey}:${env.seq}`;
      if (this.seenKeys.has(dedupeKey)) return; // exact replay — the only drop

      let msg: DecryptedMessage;
      try {
        msg = await openMessage(key, env, this.opts.identity.pubB64);
      } catch {
        this.undecryptableCount += 1;
        this.emit('undecryptable', this.undecryptableCount);
        return;
      }

      this.seenKeys.add(dedupeKey);
      if (msg.mine && env.seq >= this.mySeq) this.mySeq = env.seq + 1;

      // Room creator = author of the earliest message (lowest relay-assigned id).
      // id ordering is relay-authoritative; the message is signed, so the pubkey
      // is authenticated.
      if (typeof env.id === 'number' && env.id < this.creatorMinId) {
        this.creatorMinId = env.id;
        if (this.creatorPub !== env.pubkey) {
          this.creatorPub = env.pubkey;
          this.emit('creator', env.pubkey);
        }
      }

      // Persisted presence line (join/left): rode in as an encrypted envelope, so
      // the relay only ever saw ciphertext. Surface as a system event, not a bubble.
      if (msg.sys) {
        const ev: ChatSystemEvent = {
          type: msg.sys,
          username: msg.username,
          fingerprint: msg.fingerprint,
          pubkey: msg.pubkey,
          ts: msg.ts,
          key: dedupeKey,
        };
        this.emit('system', ev);
        return;
      }

      // Edit/delete CONTROL messages. Honored only against the author's OWN target
      // (the signature proved the author) AND a target seq the author has reached
      // (ref.s < this control message's seq). They never render as their own line.
      if (msg.editOf) {
        if (msg.editOf.p === env.pubkey && msg.editOf.s < env.seq) {
          this.applyEdit(msg.editOf, msg.text);
        }
        return;
      }
      if (msg.deleteOf) {
        if (msg.deleteOf.p === env.pubkey && msg.deleteOf.s < env.seq) {
          this.applyDelete(msg.deleteOf);
        }
        return;
      }

      // Normal message — settle against any edit/delete already known for it.
      const m2: ChatMessage = { ...msg, key: dedupeKey };
      if (this.deletedKeys.has(dedupeKey)) {
        m2.deleted = true; // delete wins regardless of arrival order
      } else {
        const pe = this.pendingEdits.get(dedupeKey);
        if (pe !== undefined) {
          m2.text = pe;
          m2.edited = true;
          this.pendingEdits.delete(dedupeKey);
        }
      }
      this.msgList.push(m2);
      this.byKey.set(dedupeKey, m2);
      this.emit('message', m2);
    });
  }

  // Apply an edit to its target. The caller verified the author owns the target.
  // If the target hasn't arrived yet, buffer it and apply on arrival.
  private applyEdit(ref: MsgRef, text: string): void {
    const tkey = `${ref.p}:${ref.s}`;
    if (this.deletedKeys.has(tkey)) return; // delete is terminal — never un-delete
    const existing = this.byKey.get(tkey);
    if (!existing) {
      if (this.pendingEdits.size >= ChatClient.PENDING_CAP) {
        this.pendingEdits.delete(
          this.pendingEdits.keys().next().value as string,
        );
      }
      this.pendingEdits.set(tkey, text);
      return;
    }
    if (existing.deleted) return;
    existing.text = text; // same object lives in msgList + byKey — both update
    existing.edited = true;
    this.emit('edit', existing);
  }

  // Tombstone a message. Terminal and order-independent — wins over any edit.
  private applyDelete(ref: MsgRef): void {
    const tkey = `${ref.p}:${ref.s}`;
    this.deletedKeys.add(tkey);
    this.pendingEdits.delete(tkey);
    const existing = this.byKey.get(tkey);
    if (!existing) return; // not arrived yet — caught on arrival via deletedKeys
    existing.deleted = true;
    this.emit('delete', existing);
  }

  // Seal + send a relay-blind presence line (join/left) as an encrypted envelope.
  private async sendSys(kind: 'join' | 'leave'): Promise<void> {
    const sock = this.ws;
    const key = this.key;
    if (!sock || sock.readyState !== WebSocket.OPEN || !key) return;
    const seq = this.mySeq++;
    const env = await sealMessage(
      key,
      this.opts.identity,
      this.rid,
      seq,
      this.opts.username,
      '',
      { sys: kind },
    );
    try {
      sock.send(JSON.stringify({ t: 'msg', env }));
    } catch {
      // socket closed underneath us — best effort.
    }
  }

  private handleRoster(entries: PresenceEntry[]): void {
    this.enqueue(async () => {
      const key = this.key;
      if (!key) return;
      this.roster.clear();
      for (const e of entries) {
        if (!e.pid) continue;
        try {
          const m = await openPresence(key, this.rid, e);
          this.roster.set(e.pid, { ...m, pid: e.pid });
        } catch {
          // bad sig / can't decrypt → skip (don't trust unverifiable presence)
        }
      }
      this.emit('roster', this.members);
    });
  }

  private handleJoin(entry: PresenceEntry): void {
    this.enqueue(async () => {
      const key = this.key;
      if (!key || !entry.pid) return;
      let m: PresenceMember;
      try {
        m = await openPresence(key, this.rid, entry);
      } catch {
        return;
      }
      this.roster.set(entry.pid, { ...m, pid: entry.pid });
      this.emit('join', m);
      this.emit('roster', this.members);
    });
  }

  private handleLeave(pid: string): void {
    // Route through the same serial queue as join/roster so a leave that arrives
    // right after a join observes the join's (async-decrypted) roster write —
    // otherwise a quick join→leave for the same pid leaves a ghost member online.
    this.enqueue(async () => {
      const m = this.roster.get(pid);
      if (!m) return;
      this.roster.delete(pid);
      this.emit('leave', m);
      this.emit('roster', this.members);
    });
  }

  /**
   * Encrypt, sign, and publish a message.
   *
   * If history replay hasn't finished yet, the message is QUEUED and flushed on
   * `ready` — sending earlier would pick a `seq` that collides with our own
   * unreplayed history, and every reader's monotonic-seq guard would drop it as
   * a replay. Returns the `seq` used (so callers can match the relay's echo to
   * confirm persistence), or null if queued / the socket isn't open.
   *
   * Pass `opts.replyTo` (a {pubkey, seq} ref) to thread the message as a reply —
   * the ref rides INSIDE the ciphertext, so the relay never sees who replied to whom.
   */
  async send(
    text: string,
    opts?: { replyTo?: MsgRef },
  ): Promise<number | null> {
    const trimmed = text.trim();
    if (!trimmed) return null;
    if (!this.historyDone) {
      this.pendingSends.push({ text: trimmed, replyTo: opts?.replyTo });
      return null;
    }
    return this.doSend(trimmed, opts?.replyTo);
  }

  private async doSend(text: string, replyTo?: MsgRef): Promise<number | null> {
    const sock = this.ws;
    const key = this.key;
    if (!sock || sock.readyState !== WebSocket.OPEN || !key) return null;
    // Allocate the seq synchronously (before the await) so concurrent sends
    // can't read the same value and emit a duplicate seq.
    const seq = this.mySeq++;
    const meta: MessageMeta | undefined = replyTo ? { replyTo } : undefined;
    const env = await sealMessage(
      key,
      this.opts.identity,
      this.rid,
      seq,
      this.opts.username,
      text,
      meta,
    );
    sock.send(JSON.stringify({ t: 'msg', env }));
    return seq;
  }

  /** Close the socket and stop reconnecting. For an announced long-lived session,
   *  persist a "left" line first (encrypted; relay-blind), then close.
   *
   *  Returns a promise that resolves only after the "left" envelope has been sealed
   *  and written to the socket. Callers that exit the process (the CLI's asyncParser
   *  runs `process.exit(0)` as soon as the action resolves) MUST await this — sealing
   *  is async (crypto on the threadpool), and process.exit would otherwise kill the
   *  in-flight send before the line reaches the relay. */
  async close(): Promise<void> {
    this.intentionalClose = true;
    this.alive = false;
    if (this.pingTimer) clearInterval(this.pingTimer);
    if (this.retryTimer) clearTimeout(this.retryTimer);
    if (this.connectTimer) clearTimeout(this.connectTimer);
    const sock = this.ws;
    if (
      this.opts.announcePresence &&
      this.announced &&
      sock &&
      sock.readyState === WebSocket.OPEN &&
      this.key
    ) {
      await this.sendSys('leave'); // flush the encrypted "left" line before closing
    }
    try {
      this.ws?.close();
    } catch {
      // already closing — ignore.
    }
  }
}


// ── Deterministic identities for hosted participants ─────────────────────────

/**
 * Derive a stable Ed25519 identity from a secret seed and a label, so a hosted
 * participant (a swarm agent run by the platform bridge) keeps the same
 * fingerprint across restarts and hosts: members verify it once, TOFU holds.
 *
 * HKDF-SHA-256(ikm = seed bytes, salt = 'af-e2ee-participant-v1', info = label)
 * → 32-byte private key. Different labels under one seed never collide; the
 * seed never leaves the caller. `seedHex` is 64 hex chars (32 bytes).
 */
export async function deriveIdentityFromSeed(
  seedHex: string,
  label: string,
): Promise<Identity> {
  if (!/^[0-9a-fA-F]{64}$/.test(seedHex)) {
    throw new Error('participant_seed_invalid');
  }
  if (!label || label.length > 128) throw new Error('participant_label_invalid');
  const { hkdfSync } = await import('node:crypto');
  const priv = new Uint8Array(
    hkdfSync(
      'sha256',
      Buffer.from(seedHex, 'hex'),
      Buffer.from('af-e2ee-participant-v1', 'utf8'),
      Buffer.from(label, 'utf8'),
      32,
    ),
  );
  return identityFromPrivateKey(priv);
}
