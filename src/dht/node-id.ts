import { sha256 } from '@noble/hashes/sha2.js';
import type { PeerId } from '@libp2p/interface';

export const NODE_ID_LEN = 32;

export type NodeID = Uint8Array; // always 32 bytes

/** Derive a Kademlia NodeID from a PeerId via SHA256(multihash bytes). */
export function idFromPeer(peerId: PeerId): NodeID {
  return sha256(peerId.toMultihash().bytes);
}

/** Derive a Kademlia NodeID from a DHT key string. */
export function idFromKey(key: string): NodeID {
  return sha256(new TextEncoder().encode(key));
}

/** XOR distance between two NodeIDs. */
export function xor(a: NodeID, b: NodeID): NodeID {
  const r = new Uint8Array(NODE_ID_LEN);
  for (let i = 0; i < NODE_ID_LEN; i++) r[i] = a[i]! ^ b[i]!;
  return r;
}

/** Leading zero bits in XOR(a, b) — the bucket index for routing. */
export function commonPrefixLen(a: NodeID, b: NodeID): number {
  const d = xor(a, b);
  for (let i = 0; i < NODE_ID_LEN; i++) {
    const v = d[i]!;
    if (v !== 0) {
      return i * 8 + (Math.clz32(v) - 24);
    }
  }
  return NODE_ID_LEN * 8;
}

/** Returns true if a is strictly closer to target than b in XOR metric. */
export function closer(a: NodeID, b: NodeID, target: NodeID): boolean {
  const da = xor(a, target);
  const db = xor(b, target);
  for (let i = 0; i < NODE_ID_LEN; i++) {
    if (da[i] !== db[i]) return da[i]! < db[i]!;
  }
  return false;
}
