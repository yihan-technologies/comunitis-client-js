import { describe, it, expect } from 'vitest';
import { peerIdFromString } from '@libp2p/peer-id';
import { RoutingTable, K, type PeerEntry } from './routing-table.js';
import { idFromPeer, idFromKey, closer, NODE_ID_LEN } from './node-id.js';

const KNOWN_PEER_IDS = [
  '12D3KooWKnDdG3iXw9eTFijk3EWSunZcFi54Zka4wmtqtt6rPxc8',
  '12D3KooWBPD6vAW9GqGYqpWFnhFGcf5XEBxDmHBjX7J3D7K4rTEy',
];

function makeEntry(tag: string): PeerEntry {
  return {
    peerId: { equals: (o: any) => o?._tag === tag, toMultihash: () => ({ bytes: new TextEncoder().encode(tag) }), toString: () => tag, _tag: tag } as any,
    nodeId: idFromKey(tag),
    addrs: [],
  };
}

describe('RoutingTable', () => {
  it('starts empty', () => {
    const rt = new RoutingTable(idFromKey('self'));
    expect(rt.size()).toBe(0);
  });

  it('adds peers', () => {
    const rt = new RoutingTable(idFromKey('self'));
    rt.add(makeEntry('a'));
    rt.add(makeEntry('b'));
    expect(rt.size()).toBe(2);
  });

  it('skips self', () => {
    const selfId = idFromKey('me');
    const rt = new RoutingTable(selfId);
    rt.add({ peerId: {} as any, nodeId: selfId, addrs: [] });
    expect(rt.size()).toBe(0);
  });

  it('does not duplicate on re-add (refresh)', () => {
    const rt = new RoutingTable(idFromKey('self'));
    const p = makeEntry('peer1');
    rt.add(p);
    rt.add(p);
    expect(rt.size()).toBe(1);
  });

  it('removes a peer', () => {
    const rt = new RoutingTable(idFromKey('self'));
    const p = makeEntry('gamma');
    rt.add(p);
    rt.remove(p.peerId, p.nodeId);
    expect(rt.size()).toBe(0);
  });

  it('caps bucket at K via LRU eviction', () => {
    // Use all-zero self; fill bucket 0 with peers whose first bit is 1.
    const self = new Uint8Array(NODE_ID_LEN);
    const rt = new RoutingTable(self);

    for (let i = 0; i <= K; i++) {
      const nid = new Uint8Array(NODE_ID_LEN);
      nid[0] = 0x80;
      nid[1] = i;
      rt.add({ peerId: { equals: () => false, toString: () => `p${i}` } as any, nodeId: nid, addrs: [] });
    }

    expect(rt.size()).toBe(K);
  });

  it('closestPeers returns sorted results', () => {
    const rt = new RoutingTable(idFromKey('self'));
    for (let i = 0; i < 25; i++) rt.add(makeEntry(`node-${i}`));
    const target = idFromKey('search-key');
    const closest = rt.closestPeers(target, K);
    expect(closest.length).toBe(K);

    for (let i = 1; i < closest.length; i++) {
      expect(closer(closest[i]!.nodeId, closest[i - 1]!.nodeId, target)).toBe(false);
    }
  });

  it('closestPeers returns fewer than K when table is small', () => {
    const rt = new RoutingTable(idFromKey('self'));
    rt.add(makeEntry('only'));
    expect(rt.closestPeers(idFromKey('q'), K)).toHaveLength(1);
  });
});
