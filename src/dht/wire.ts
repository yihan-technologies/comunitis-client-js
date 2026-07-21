/**
 * Wire protocol for the comunitis Kademlia DHT.
 *
 * Frame format (over libp2p streams):
 *   [4 bytes BE: payload length]
 *   [1 byte: message type]
 *   [payload bytes]
 *
 * One request frame per stream, one response frame per stream.
 */

import type { PeerId } from '@libp2p/interface';
import type { Multiaddr } from '@multiformats/multiaddr';
import { multiaddr } from '@multiformats/multiaddr';
import { peerIdFromMultihash } from '@libp2p/peer-id';
import { decode as decodeMultihash } from 'multiformats/hashes/digest';
import { type NodeID, idFromPeer } from './node-id.js';
import type { PeerEntry } from './routing-table.js';

export const MSG_PING        = 0x01;
export const MSG_PONG        = 0x02;
export const MSG_FIND_NODE   = 0x03;
export const MSG_NODES       = 0x04;
export const MSG_STORE       = 0x05;
export const MSG_STORE_ACK   = 0x06;
export const MSG_FIND_VALUE  = 0x07;
export const MSG_VALUE       = 0x08;
export const MSG_VALUE_NODES = 0x09;

export interface Frame {
  type: number;
  payload: Uint8Array;
}

// --- frame codec ---

export function encodeFrame(f: Frame): Uint8Array {
  const total = 1 + f.payload.length;
  const buf = new Uint8Array(4 + total);
  const view = new DataView(buf.buffer);
  view.setUint32(0, total, false); // BE
  buf[4] = f.type;
  buf.set(f.payload, 5);
  return buf;
}

/** Read one frame from a flat byte array. Returns null if data is incomplete. */
export function decodeFrame(data: Uint8Array): { frame: Frame; rest: Uint8Array } | null {
  if (data.length < 5) return null;
  const view = new DataView(data.buffer, data.byteOffset);
  const total = view.getUint32(0, false);
  if (data.length < 4 + total) return null;
  const frame: Frame = {
    type: data[4]!,
    payload: data.slice(5, 4 + total),
  };
  return { frame, rest: data.slice(4 + total) };
}

// --- peer record codec ---

/** Encode one PeerEntry as a peer record.
 * Format: [u16 peerIDLen][peerID multihash bytes][u8 addrCount][addrCount × ([u16 addrLen][addrBytes])]
 */
export function encodePeerRecord(p: PeerEntry): Uint8Array {
  const pidBytes = p.peerId.toMultihash().bytes;
  const addrBufs = p.addrs.map(a => a.bytes);
  const size = 2 + pidBytes.length + 1 + addrBufs.reduce((s, a) => s + 2 + a.length, 0);
  const buf = new Uint8Array(size);
  const view = new DataView(buf.buffer);
  let off = 0;
  view.setUint16(off, pidBytes.length, false); off += 2;
  buf.set(pidBytes, off); off += pidBytes.length;
  buf[off++] = Math.min(addrBufs.length, 255);
  for (const ab of addrBufs) {
    view.setUint16(off, ab.length, false); off += 2;
    buf.set(ab, off); off += ab.length;
  }
  return buf;
}

/** Decode a NODES payload: [u8 count][count × PeerRecord] */
export function decodePeerRecords(payload: Uint8Array): PeerEntry[] {
  if (payload.length < 1) return [];
  const count = payload[0]!;
  const view = new DataView(payload.buffer, payload.byteOffset);
  let off = 1;
  const out: PeerEntry[] = [];
  for (let i = 0; i < count; i++) {
    if (off + 2 > payload.length) break;
    const pidLen = view.getUint16(off, false); off += 2;
    if (off + pidLen > payload.length) break;
    const pidBytes = payload.slice(off, off + pidLen); off += pidLen;
    if (off + 1 > payload.length) break;
    const addrCount = payload[off++]!;
    const addrs: Multiaddr[] = [];
    for (let j = 0; j < addrCount; j++) {
      if (off + 2 > payload.length) break;
      const addrLen = view.getUint16(off, false); off += 2;
      if (off + addrLen > payload.length) break;
      try { addrs.push(multiaddr(payload.slice(off, off + addrLen))); } catch { /* skip */ }
      off += addrLen;
    }
    try {
      const mh = decodeMultihash(pidBytes);
      const peerId = peerIdFromMultihash(mh);
      out.push({ peerId, nodeId: idFromPeer(peerId), addrs });
    } catch (e) {
      console.warn('[dht] decodePeerRecords: skipping invalid peer record:', e);
    }
  }
  return out;
}

/** Build a NODES payload from up to 255 peers. */
export function encodeNodesPayload(peers: PeerEntry[]): Uint8Array {
  const capped = peers.slice(0, 255);
  const recs = capped.map(encodePeerRecord);
  const size = 1 + recs.reduce((s, r) => s + r.length, 0);
  const buf = new Uint8Array(size);
  buf[0] = capped.length;
  let off = 1;
  for (const r of recs) { buf.set(r, off); off += r.length; }
  return buf;
}

/** Encode a STORE payload: [u16 keyLen][key][u32 valLen][val][u32 ttlSecs] */
export function encodeStorePayload(key: string, value: Uint8Array, ttlSecs: number): Uint8Array {
  const kb = new TextEncoder().encode(key);
  const buf = new Uint8Array(2 + kb.length + 4 + value.length + 4);
  const view = new DataView(buf.buffer);
  let off = 0;
  view.setUint16(off, kb.length, false); off += 2;
  buf.set(kb, off); off += kb.length;
  view.setUint32(off, value.length, false); off += 4;
  buf.set(value, off); off += value.length;
  view.setUint32(off, ttlSecs, false);
  return buf;
}

/** Encode a [u16 keyLen][key] payload for FIND_VALUE. */
export function encodeKeyPayload(key: string): Uint8Array {
  const kb = new TextEncoder().encode(key);
  const buf = new Uint8Array(2 + kb.length);
  new DataView(buf.buffer).setUint16(0, kb.length, false);
  buf.set(kb, 2);
  return buf;
}

/** Encode a [u32 valLen][val] VALUE response payload. */
export function encodeValuePayload(value: Uint8Array): Uint8Array {
  const buf = new Uint8Array(4 + value.length);
  new DataView(buf.buffer).setUint32(0, value.length, false);
  buf.set(value, 4);
  return buf;
}

export function decodeValuePayload(p: Uint8Array): Uint8Array | null {
  if (p.length < 4) return null;
  const vlen = new DataView(p.buffer, p.byteOffset).getUint32(0, false);
  if (4 + vlen > p.length) return null;
  return p.slice(4, 4 + vlen);
}
