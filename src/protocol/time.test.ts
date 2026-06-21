import { describe, it, expect } from 'vitest';
import { encodeTime, decodeTime } from './time.js';

describe('encodeTime / decodeTime', () => {
  it('roundtrips current time within 1s', () => {
    const before = Date.now();
    const buf = encodeTime();
    const decoded = decodeTime(buf);
    const after = Date.now();
    expect(decoded.getTime()).toBeGreaterThanOrEqual(before);
    expect(decoded.getTime()).toBeLessThanOrEqual(after);
  });

  it('encodes a specific date correctly', () => {
    const d = new Date('2024-01-15T12:00:00.000Z');
    const buf = encodeTime(d);
    expect(buf.byteLength).toBe(8);
    const decoded = decodeTime(buf);
    expect(decoded.getTime()).toBe(d.getTime());
  });

  it('little-endian encoding', () => {
    // 1000 ms = 0x03E8 — first byte should be 0xE8, second 0x03
    const d = new Date(1000);
    const buf = encodeTime(d);
    expect(buf[0]).toBe(0xe8);
    expect(buf[1]).toBe(0x03);
    expect(buf[2]).toBe(0x00);
  });

  it('zero epoch', () => {
    const d = new Date(0);
    const buf = encodeTime(d);
    expect(buf).toEqual(new Uint8Array(8));
    expect(decodeTime(buf).getTime()).toBe(0);
  });
});
