import { describe, it, expect } from 'vitest';
import { requestSignBytes, responseSignBytes, signRequest, signResponse, verifyResponse } from './signing.js';
import { generateSigningKey, verifyBytes } from '../keymanager/crypto.js';

describe('requestSignBytes', () => {
  it('has correct length: idBytes + 8 + dataBytes', () => {
    const id = 'abc';
    const time = new Uint8Array(8).fill(1);
    const data = new Uint8Array([10, 20]);
    const msg = requestSignBytes(id, time, data);
    expect(msg.byteLength).toBe(3 + 8 + 2);
  });

  it('contains requestId at start', () => {
    const id = 'hello';
    const time = new Uint8Array(8);
    const data = new Uint8Array(0);
    const msg = requestSignBytes(id, time, data);
    const idBytes = new TextEncoder().encode(id);
    expect(msg.slice(0, 5)).toEqual(idBytes);
  });
});

describe('responseSignBytes', () => {
  it('has correct length: id + 8 + data + 4 + errStr', () => {
    const id = 'xy';
    const time = new Uint8Array(8);
    const data = new Uint8Array([1, 2, 3]);
    const errStr = 'oops';
    const msg = responseSignBytes(id, time, data, 5, errStr);
    expect(msg.byteLength).toBe(2 + 8 + 3 + 4 + 4);
  });
});

describe('signRequest / verifyResponse', () => {
  it('generates verifiable signature', () => {
    const { pub, priv } = generateSigningKey();
    const requestId = 'test-req-id';
    const data = new Uint8Array([1, 2, 3]);
    const { time, signature } = signRequest(priv, requestId, data);

    // Rebuild signed bytes and verify manually
    const msg = requestSignBytes(requestId, time, data);
    expect(verifyBytes(pub, msg, signature)).toBe(true);
  });

  it('rejects tampered data', () => {
    const { pub, priv } = generateSigningKey();
    const requestId = 'test-req-id';
    const data = new Uint8Array([1, 2, 3]);
    const { time, signature } = signRequest(priv, requestId, data);

    const tampered = new Uint8Array([1, 2, 4]); // last byte changed
    const msg = requestSignBytes(requestId, time, tampered);
    expect(verifyBytes(pub, msg, signature)).toBe(false);
  });
});

describe('signResponse / verifyResponse', () => {
  it('generates verifiable response signature', () => {
    const { pub, priv } = generateSigningKey();
    const requestId = 'resp-id';
    const timeMs = BigInt(Date.now());
    const data = new Uint8Array([9, 8, 7]);

    const signature = signResponse(priv, requestId, timeMs, data);

    // Reconstruct timeBuf
    const timeBuf = new Uint8Array(8);
    new DataView(timeBuf.buffer).setBigInt64(0, timeMs, true);

    expect(verifyResponse(pub, requestId, timeBuf, data, signature)).toBe(true);
  });

  it('rejects wrong time in verify', () => {
    const { pub, priv } = generateSigningKey();
    const requestId = 'resp-id';
    const timeMs = BigInt(Date.now());
    const data = new Uint8Array([1]);

    const signature = signResponse(priv, requestId, timeMs, data);

    // Verify with different time
    const wrongTimeBuf = new Uint8Array(8).fill(0xff);
    expect(verifyResponse(pub, requestId, wrongTimeBuf, data, signature)).toBe(false);
  });
});
