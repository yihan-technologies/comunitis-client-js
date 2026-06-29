import type { PeerId } from '@libp2p/interface';
import type { Multiaddr } from '@multiformats/multiaddr';
import { type NodeID, idFromPeer, commonPrefixLen, closer, NODE_ID_LEN } from './node-id.js';

export const K = 20;
export const ALPHA = 3;

export interface PeerEntry {
  peerId: PeerId;
  nodeId: NodeID;
  addrs: Multiaddr[];
}

class KBucket {
  peers: PeerEntry[] = []; // LRU: tail = most recently seen

  add(p: PeerEntry): void {
    const idx = this.peers.findIndex(e => e.peerId.equals(p.peerId));
    if (idx >= 0) {
      this.peers.splice(idx, 1);
    } else if (this.peers.length >= K) {
      this.peers.shift(); // evict LRU head
    }
    this.peers.push(p);
  }

  remove(peerId: PeerId): void {
    const idx = this.peers.findIndex(e => e.peerId.equals(peerId));
    if (idx >= 0) this.peers.splice(idx, 1);
  }

  snapshot(): PeerEntry[] {
    return [...this.peers];
  }
}

export class RoutingTable {
  private self: NodeID;
  private buckets: KBucket[];

  constructor(selfId: NodeID) {
    this.self = selfId;
    this.buckets = Array.from({ length: NODE_ID_LEN * 8 }, () => new KBucket());
  }

  private bucketIdx(id: NodeID): number {
    return Math.min(commonPrefixLen(this.self, id), this.buckets.length - 1);
  }

  add(p: PeerEntry): void {
    if (p.nodeId.every((b, i) => b === this.self[i])) return; // skip self
    this.buckets[this.bucketIdx(p.nodeId)]!.add(p);
  }

  remove(peerId: PeerId, nodeId: NodeID): void {
    this.buckets[this.bucketIdx(nodeId)]!.remove(peerId);
  }

  closestPeers(target: NodeID, n: number): PeerEntry[] {
    const all = this.buckets.flatMap(b => b.snapshot());
    all.sort((a, b) => closer(a.nodeId, b.nodeId, target) ? -1 : 1);
    return all.slice(0, n);
  }

  size(): number {
    return this.buckets.reduce((s, b) => s + b.peers.length, 0);
  }
}
