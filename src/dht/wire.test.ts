import { describe, it, expect } from 'vitest';
import { peerIdFromString } from '@libp2p/peer-id';
import { multiaddr } from '@multiformats/multiaddr';
import type { PeerEntry } from './routing-table.js';
import { idFromPeer, idFromKey } from './node-id.js';
import {
  MSG_PING, MSG_PONG, MSG_NODES, MSG_STORE, MSG_FIND_VALUE, MSG_VALUE,
  encodeFrame, decodeFrame,
  encodePeerRecord, decodePeerRecords, encodeNodesPayload,
  encodeStorePayload, encodeKeyPayload, encodeValuePayload, decodeValuePayload,
} from './wire.js';

const TEST_PEER_ID = '12D3KooWKnDdG3iXw9eTFijk3EWSunZcFi54Zka4wmtqtt6rPxc8';

function makePeer(peerIdStr = TEST_PEER_ID, addrStrs: string[] = []): PeerEntry {
  const pid = peerIdFromString(peerIdStr);
  return { peerId: pid, nodeId: idFromPeer(pid), addrs: addrStrs.map(a => multiaddr(a)) };
}

// --- Frame roundtrip ---

describe('encodeFrame / decodeFrame', () => {
  it('roundtrips empty payload (PING)', () => {
    const encoded = encodeFrame({ type: MSG_PING, payload: new Uint8Array(0) });
    const result = decodeFrame(encoded);
    expect(result).not.toBeNull();
    expect(result!.frame.type).toBe(MSG_PING);
    expect(result!.frame.payload).toHaveLength(0);
  });

  it('roundtrips a payload (NODES)', () => {
    const payload = new Uint8Array([1, 2, 3, 4]);
    const encoded = encodeFrame({ type: MSG_NODES, payload });
    const result = decodeFrame(encoded);
    expect(result!.frame.type).toBe(MSG_NODES);
    expect(result!.frame.payload).toEqual(payload);
  });

  it('returns null for incomplete data', () => {
    expect(decodeFrame(new Uint8Array(3))).toBeNull();
    expect(decodeFrame(new Uint8Array(0))).toBeNull();
  });

  it('rest is empty when exactly one frame', () => {
    const encoded = encodeFrame({ type: MSG_PONG, payload: new Uint8Array(0) });
    const result = decodeFrame(encoded);
    expect(result!.rest).toHaveLength(0);
  });

  it('parses multiple concatenated frames via rest', () => {
    const f1 = encodeFrame({ type: MSG_PING, payload: new Uint8Array(0) });
    const f2 = encodeFrame({ type: MSG_PONG, payload: new Uint8Array([99]) });
    const combined = new Uint8Array([...f1, ...f2]);

    const r1 = decodeFrame(combined)!;
    expect(r1.frame.type).toBe(MSG_PING);
    const r2 = decodeFrame(r1.rest)!;
    expect(r2.frame.type).toBe(MSG_PONG);
    expect(r2.frame.payload[0]).toBe(99);
  });
});

// --- PeerRecord roundtrip ---

describe('encodePeerRecord / decodePeerRecords', () => {
  it('roundtrips one peer with no addrs', () => {
    const p = makePeer();
    const payload = encodeNodesPayload([p]);
    const peers = decodePeerRecords(payload);
    expect(peers).toHaveLength(1);
    expect(peers[0]!.peerId.equals(p.peerId)).toBe(true);
    expect(peers[0]!.addrs).toHaveLength(0);
  });

  it('roundtrips one peer with multiaddr', () => {
    const p = makePeer(TEST_PEER_ID, ['/ip4/127.0.0.1/tcp/4001']);
    const payload = encodeNodesPayload([p]);
    const peers = decodePeerRecords(payload);
    expect(peers[0]!.addrs).toHaveLength(1);
    expect(peers[0]!.addrs[0]!.toString()).toBe('/ip4/127.0.0.1/tcp/4001');
  });

  it('roundtrips multiple peers', () => {
    const peers = [
      makePeer(TEST_PEER_ID),
      makePeer(TEST_PEER_ID, ['/ip4/1.2.3.4/tcp/9000']),
    ];
    const payload = encodeNodesPayload(peers);
    const got = decodePeerRecords(payload);
    expect(got).toHaveLength(2);
    expect(got[0]!.peerId.equals(peers[0]!.peerId)).toBe(true);
    expect(got[1]!.peerId.equals(peers[1]!.peerId)).toBe(true);
  });

  it('handles empty payload', () => {
    expect(decodePeerRecords(new Uint8Array(0))).toEqual([]);
  });

  it('handles zero-count payload', () => {
    expect(decodePeerRecords(new Uint8Array([0]))).toEqual([]);
  });

  it('caps at 255 peers in encoding', () => {
    const peers = Array.from({ length: 260 }, () => makePeer());
    const payload = encodeNodesPayload(peers);
    expect(payload[0]).toBe(255);
  });
});

// --- StorePayload ---

describe('encodeStorePayload', () => {
  it('encodes key, value, and TTL in order', () => {
    const key = '/cn/abc';
    const val = new TextEncoder().encode('data');
    const ttl = 3600;
    const p = encodeStorePayload(key, val, ttl);

    // key length at offset 0 (u16 BE)
    const view = new DataView(p.buffer);
    const klen = view.getUint16(0, false);
    expect(klen).toBe(key.length);

    const keyDecoded = new TextDecoder().decode(p.slice(2, 2 + klen));
    expect(keyDecoded).toBe(key);

    const vlen = view.getUint32(2 + klen, false);
    expect(vlen).toBe(val.length);

    const ttlGot = view.getUint32(2 + klen + 4 + vlen, false);
    expect(ttlGot).toBe(ttl);
  });
});

// --- KeyPayload ---

describe('encodeKeyPayload', () => {
  it('prepends u16 length then key bytes', () => {
    const key = '/peer/xyz';
    const p = encodeKeyPayload(key);
    const view = new DataView(p.buffer);
    const klen = view.getUint16(0, false);
    expect(klen).toBe(key.length);
    expect(new TextDecoder().decode(p.slice(2))).toBe(key);
  });
});

// --- ValuePayload roundtrip ---

describe('encodeValuePayload / decodeValuePayload', () => {
  it('roundtrips non-empty value', () => {
    const val = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);
    const got = decodeValuePayload(encodeValuePayload(val));
    expect(got).toEqual(val);
  });

  it('roundtrips empty value', () => {
    const got = decodeValuePayload(encodeValuePayload(new Uint8Array(0)));
    expect(got).not.toBeNull();
    expect(got).toHaveLength(0);
  });

  it('returns null for truncated payload', () => {
    expect(decodeValuePayload(new Uint8Array(2))).toBeNull();
    expect(decodeValuePayload(new Uint8Array(0))).toBeNull();
  });
});
