import { describe, it, expect } from 'vitest';
import { idFromKey, idFromPeer, xor, commonPrefixLen, closer, NODE_ID_LEN } from './node-id.js';
import { peerIdFromString } from '@libp2p/peer-id';

const pid = peerIdFromString('12D3KooWKnDdG3iXw9eTFijk3EWSunZcFi54Zka4wmtqtt6rPxc8');

describe('idFromKey', () => {
  it('returns 32 bytes', () => {
    const id = idFromKey('hello');
    expect(id).toHaveLength(NODE_ID_LEN);
  });

  it('is deterministic', () => {
    expect(idFromKey('hello')).toEqual(idFromKey('hello'));
  });

  it('differs for different keys', () => {
    expect(idFromKey('a')).not.toEqual(idFromKey('b'));
  });
});

describe('idFromPeer', () => {
  it('returns 32 bytes', () => {
    expect(idFromPeer(pid)).toHaveLength(NODE_ID_LEN);
  });

  it('is deterministic', () => {
    expect(idFromPeer(pid)).toEqual(idFromPeer(pid));
  });
});

describe('xor', () => {
  it('XOR(a, a) = zero', () => {
    const a = idFromKey('x');
    const z = xor(a, a);
    expect(z.every(b => b === 0)).toBe(true);
  });

  it('XOR is symmetric', () => {
    const a = idFromKey('foo');
    const b = idFromKey('bar');
    expect(xor(a, b)).toEqual(xor(b, a));
  });

  it('XOR(a, 0) = a', () => {
    const a = idFromKey('test');
    const zero = new Uint8Array(NODE_ID_LEN);
    expect(xor(a, zero)).toEqual(a);
  });
});

describe('commonPrefixLen', () => {
  it('CPL(self, self) = 256', () => {
    const a = idFromKey('same');
    expect(commonPrefixLen(a, a)).toBe(NODE_ID_LEN * 8);
  });

  it('CPL is in [0, 256]', () => {
    const a = idFromKey('p');
    const b = idFromKey('q');
    const cpl = commonPrefixLen(a, b);
    expect(cpl).toBeGreaterThanOrEqual(0);
    expect(cpl).toBeLessThanOrEqual(NODE_ID_LEN * 8);
  });

  it('CPL for all-zero vs 0x80 first byte = 0', () => {
    const a = new Uint8Array(NODE_ID_LEN);          // 00000000...
    const b = new Uint8Array(NODE_ID_LEN);
    b[0] = 0x80;                                     // 10000000...
    expect(commonPrefixLen(a, b)).toBe(0);
  });

  it('CPL for same first byte, different second = 8', () => {
    const a = new Uint8Array(NODE_ID_LEN);
    const b = new Uint8Array(NODE_ID_LEN);
    // first bytes equal (0x00), second bytes differ in MSB
    b[1] = 0x80;
    expect(commonPrefixLen(a, b)).toBe(8);
  });
});

describe('closer', () => {
  it('returns false when a equals b', () => {
    const a = idFromKey('x');
    const t = idFromKey('t');
    expect(closer(a, a, t)).toBe(false);
  });

  it('cannot be closer in both directions', () => {
    const a = idFromKey('n1');
    const b = idFromKey('n2');
    const t = idFromKey('target');
    expect(closer(a, b, t) && closer(b, a, t)).toBe(false);
  });
});
