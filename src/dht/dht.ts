/**
 * ComunitisKadDHT — custom Kademlia DHT for the comunitis client.
 *
 * Protocol IDs (matching the Go server):
 *   Server-facing: /comunitis/kad/server/1.0.0
 *   Client-facing: /comunitis/kad/client/1.0.0
 *
 * Comunitis DHT key namespaces:
 *   /cc/<pubKey>     — comuniti-creation handshake
 *   /cn/<comunitiID> — servers hosting a comuniti
 *   /peer/<peerID>   — peer address record
 *   /prov/<key>      — content provider list (for libp2p rendezvous)
 */

import type { Libp2p, PeerId, Stream } from '@libp2p/interface';
import type { Uint8ArrayList } from 'uint8arraylist';
import { idFromPeer, idFromKey, type NodeID } from './node-id.js';
import { RoutingTable, type PeerEntry, K, ALPHA } from './routing-table.js';
import {
  MSG_PING, MSG_PONG, MSG_FIND_NODE, MSG_NODES,
  MSG_STORE, MSG_STORE_ACK, MSG_FIND_VALUE, MSG_VALUE, MSG_VALUE_NODES,
  encodeFrame, decodeFrame, decodePeerRecords, encodeNodesPayload,
  encodeStorePayload, encodeKeyPayload, encodeValuePayload, decodeValuePayload,
  type Frame,
} from './wire.js';

export const SERVER_PROTOCOL = '/comunitis/kad/server/1.0.0';
export const CLIENT_PROTOCOL = '/comunitis/kad/client/1.0.0';

export const NS_COMUNITI_NODE = '/cn/';
export const NS_COMUNITI_CREA = '/cc/';
export const NS_PEER          = '/peer/';
export const NS_PROVIDER      = '/prov/';

const DEFAULT_VALUE_TTL = 86400; // 24h in seconds

interface StoreEntry {
  value: Uint8Array;
  expires: number; // Date.now() ms
}

function toUint8Array(chunk: Uint8Array | Uint8ArrayList): Uint8Array {
  return chunk instanceof Uint8Array ? chunk : chunk.subarray();
}

async function readAll(stream: Stream): Promise<Uint8Array> {
  const chunks: Uint8Array[] = [];
  for await (const chunk of stream) {
    chunks.push(toUint8Array(chunk as Uint8Array | Uint8ArrayList));
  }
  const total = chunks.reduce((s, c) => s + c.length, 0);
  const buf = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) { buf.set(c, off); off += c.length; }
  return buf;
}

async function sendAndClose(stream: Stream, data: Uint8Array): Promise<void> {
  const ok = stream.send(data);
  if (ok === false) {
    await new Promise<void>(resolve =>
      stream.addEventListener('drain', resolve as () => void, { once: true })
    );
  }
  await stream.close();
}

export class ComunitisKadDHT {
  private libp2p: Libp2p;
  private protocolId: string;
  private selfId: NodeID;
  private rt: RoutingTable;
  private store: Map<string, StoreEntry> = new Map();
  private janitor?: ReturnType<typeof setInterval>;

  constructor(libp2p: Libp2p, protocolId: string = CLIENT_PROTOCOL) {
    this.libp2p = libp2p;
    this.protocolId = protocolId;
    this.selfId = idFromPeer(libp2p.peerId);
    this.rt = new RoutingTable(this.selfId);
  }

  /** Register the protocol handler and start the store janitor. */
  async start(): Promise<void> {
    await this.libp2p.handle(this.protocolId, (data: any) => {
      const stream: Stream = data.stream ?? data;
      this.handleStream(stream).catch(() => stream.abort(new Error('dht: handler error')));
    });
    this.janitor = setInterval(() => this.evictExpired(), 5 * 60 * 1000);
    for (const pid of this.libp2p.getPeers()) {
      this.rt.add({ peerId: pid, nodeId: idFromPeer(pid), addrs: [] });
    }
  }

  /** Deregister protocol handler and stop janitor. */
  async stop(): Promise<void> {
    await this.libp2p.unhandle(this.protocolId);
    if (this.janitor) clearInterval(this.janitor);
  }

  /** Fill routing table by doing a self-lookup from current peers. */
  async refreshRoutingTable(): Promise<void> {
    for (const pid of this.libp2p.getPeers()) {
      this.rt.add({ peerId: pid, nodeId: idFromPeer(pid), addrs: [] });
    }
    await this.iterativeFindNode(this.selfId).catch(() => []);
  }

  // --- DHT operations ---

  async putValue(key: string, value: Uint8Array, ttlSecs = DEFAULT_VALUE_TTL): Promise<void> {
    this.localPut(key, value, ttlSecs);
    const target = idFromKey(key);
    const closest = await this.iterativeFindNode(target);
    await Promise.allSettled(
      closest.map(p => this.rpcStore(p, key, value, ttlSecs))
    );
  }

  async getValue(key: string): Promise<Uint8Array | null> {
    const local = this.localGet(key);
    if (local) return local;
    const [val] = await this.iterativeFindValue(key);
    return val;
  }

  /** Find servers hosting comunitiId via DHT lookup on /cn/<comunitiId>. */
  async findComunitiServers(comunitiId: string): Promise<Uint8Array | null> {
    return this.getValue(NS_COMUNITI_NODE + comunitiId);
  }

  async ping(peerId: PeerId): Promise<boolean> {
    try {
      const s = await this.libp2p.dialProtocol(peerId, this.protocolId);
      const resp = await this.exchange(s, { type: MSG_PING, payload: new Uint8Array(0) });
      return resp?.type === MSG_PONG;
    } catch { return false; }
  }

  async findPeer(peerId: PeerId): Promise<{ id: PeerId; addrs: any[] } | null> {
    const closest = await this.iterativeFindNode(idFromPeer(peerId));
    const found = closest.find(p => p.peerId.equals(peerId));
    return found ? { id: found.peerId, addrs: found.addrs } : null;
  }

  /** All peer IDs currently in the routing table. */
  getKnownPeerIds(): PeerId[] {
    return this.rt.closestPeers(this.selfId, K * 8).map(e => e.peerId);
  }

  // --- stream handler (serves incoming DHT queries) ---

  private async handleStream(stream: Stream): Promise<void> {
    const data = await readAll(stream);
    const decoded = decodeFrame(data);
    if (!decoded) return;
    const { frame } = decoded;

    // Seed routing table with the sender.
    const remote: PeerId | undefined = (stream as any).connection?.remotePeer;
    if (remote) this.rt.add({ peerId: remote, nodeId: idFromPeer(remote), addrs: [] });

    let response: Frame | null = null;

    switch (frame.type) {
      case MSG_PING:
        response = { type: MSG_PONG, payload: new Uint8Array(0) };
        break;

      case MSG_FIND_NODE: {
        if (frame.payload.length < 32) break;
        const target = frame.payload.slice(0, 32) as NodeID;
        const closest = this.rt.closestPeers(target, K);
        response = { type: MSG_NODES, payload: encodeNodesPayload(closest) };
        break;
      }

      case MSG_STORE: {
        const r = this.decodeStorePayload(frame.payload);
        if (r) {
          this.localPut(r.key, r.value, r.ttlSecs);
          response = { type: MSG_STORE_ACK, payload: new Uint8Array([0]) };
        } else {
          response = { type: MSG_STORE_ACK, payload: new Uint8Array([1]) };
        }
        break;
      }

      case MSG_FIND_VALUE: {
        const key = this.decodeKeyPayload(frame.payload);
        if (!key) break;
        const val = this.localGet(key);
        if (val) {
          response = { type: MSG_VALUE, payload: encodeValuePayload(val) };
        } else {
          const closest = this.rt.closestPeers(idFromKey(key), K);
          response = { type: MSG_VALUE_NODES, payload: encodeNodesPayload(closest) };
        }
        break;
      }
    }

    if (response) {
      await sendAndClose(stream, encodeFrame(response));
    }
  }

  // --- outgoing RPCs ---

  private async rpcFindNode(p: PeerEntry, target: NodeID): Promise<PeerEntry[]> {
    try {
      const s = await this.libp2p.dialProtocol(p.peerId, this.protocolId);
      const resp = await this.exchange(s, { type: MSG_FIND_NODE, payload: target });
      if (!resp || resp.type !== MSG_NODES) return [];
      const peers = decodePeerRecords(resp.payload);
      for (const peer of peers) this.rt.add(peer);
      return peers;
    } catch {
      this.rt.remove(p.peerId, p.nodeId);
      return [];
    }
  }

  private async rpcFindValue(p: PeerEntry, key: string): Promise<{ val: Uint8Array | null; nodes: PeerEntry[] }> {
    try {
      const s = await this.libp2p.dialProtocol(p.peerId, this.protocolId);
      const resp = await this.exchange(s, { type: MSG_FIND_VALUE, payload: encodeKeyPayload(key) });
      if (!resp) return { val: null, nodes: [] };
      if (resp.type === MSG_VALUE) return { val: decodeValuePayload(resp.payload), nodes: [] };
      if (resp.type === MSG_VALUE_NODES) {
        const nodes = decodePeerRecords(resp.payload);
        for (const peer of nodes) this.rt.add(peer);
        return { val: null, nodes };
      }
      return { val: null, nodes: [] };
    } catch { return { val: null, nodes: [] }; }
  }

  private async rpcStore(p: PeerEntry, key: string, value: Uint8Array, ttlSecs: number): Promise<boolean> {
    try {
      const s = await this.libp2p.dialProtocol(p.peerId, this.protocolId);
      const resp = await this.exchange(s, {
        type: MSG_STORE,
        payload: encodeStorePayload(key, value, ttlSecs),
      });
      return resp?.type === MSG_STORE_ACK && resp.payload[0] === 0;
    } catch { return false; }
  }

  /** Send a frame and receive the response frame. Closes write side after sending. */
  private async exchange(stream: Stream, req: Frame): Promise<Frame | null> {
    const readPromise = readAll(stream);
    await sendAndClose(stream, encodeFrame(req));
    const data = await readPromise;
    const decoded = decodeFrame(data);
    return decoded ? decoded.frame : null;
  }

  // --- iterative lookups ---

  private async iterativeFindNode(target: NodeID): Promise<PeerEntry[]> {
    const MAX_ROUNDS = 20;
    const seeds = this.rt.closestPeers(target, K);
    if (seeds.length === 0) return [];
    const queried = new Set<string>();
    let pending = [...seeds];
    let rounds = 0;

    for (;;) {
      if (rounds >= MAX_ROUNDS) break;
      rounds++;
      const batch: PeerEntry[] = [];
      const next: PeerEntry[] = [];
      for (const p of pending) {
        const key = p.peerId.toString();
        if (!queried.has(key)) {
          if (batch.length < ALPHA) batch.push(p);
          else next.push(p);
        }
      }
      pending = next;
      if (batch.length === 0) break;
      for (const p of batch) queried.add(p.peerId.toString());
      const results = await Promise.all(batch.map(p => this.rpcFindNode(p, target)));
      for (const found of results.flat()) {
        if (!queried.has(found.peerId.toString())) pending.push(found);
      }
    }
    return this.rt.closestPeers(target, K);
  }

  private async iterativeFindValue(key: string): Promise<[Uint8Array | null, PeerEntry[]]> {
    const target = idFromKey(key);
    const seeds = this.rt.closestPeers(target, K);
    const queried = new Set<string>();
    let pending = [...seeds];

    for (;;) {
      const batch: PeerEntry[] = [];
      const next: PeerEntry[] = [];
      for (const p of pending) {
        const k = p.peerId.toString();
        if (!queried.has(k)) {
          if (batch.length < ALPHA) batch.push(p);
          else next.push(p);
        }
      }
      pending = next;
      if (batch.length === 0) break;
      for (const p of batch) queried.add(p.peerId.toString());
      const results = await Promise.all(batch.map(p => this.rpcFindValue(p, key)));
      for (const r of results) {
        if (r.val) return [r.val, []];
        for (const n of r.nodes) {
          if (!queried.has(n.peerId.toString())) pending.push(n);
        }
      }
    }
    return [null, this.rt.closestPeers(target, K)];
  }

  // --- local store ---

  private localPut(key: string, value: Uint8Array, ttlSecs: number): void {
    this.store.set(key, { value, expires: Date.now() + ttlSecs * 1000 });
  }

  private localGet(key: string): Uint8Array | null {
    const e = this.store.get(key);
    if (!e || Date.now() > e.expires) return null;
    return e.value;
  }

  private evictExpired(): void {
    const now = Date.now();
    for (const [k, e] of this.store) {
      if (now > e.expires) this.store.delete(k);
    }
  }

  // --- payload decoders (inlined for clarity) ---

  private decodeStorePayload(p: Uint8Array): { key: string; value: Uint8Array; ttlSecs: number } | null {
    const view = new DataView(p.buffer, p.byteOffset);
    let off = 0;
    if (off + 2 > p.length) return null;
    const klen = view.getUint16(off, false); off += 2;
    if (off + klen > p.length) return null;
    const key = new TextDecoder().decode(p.slice(off, off + klen)); off += klen;
    if (off + 4 > p.length) return null;
    const vlen = view.getUint32(off, false); off += 4;
    if (off + vlen > p.length) return null;
    const value = p.slice(off, off + vlen); off += vlen;
    if (off + 4 > p.length) return null;
    const ttlSecs = view.getUint32(off, false);
    return { key, value, ttlSecs };
  }

  private decodeKeyPayload(p: Uint8Array): string | null {
    if (p.length < 2) return null;
    const klen = new DataView(p.buffer, p.byteOffset).getUint16(0, false);
    if (2 + klen > p.length) return null;
    return new TextDecoder().decode(p.slice(2, 2 + klen));
  }
}
