import { describe, it, expect } from 'vitest';
import { requestSignBytes, responseSignBytes, signRequest, signResponse, verifyResponse } from './signing.js';
import { generateSigningKey, verifyBytes } from '../keymanager/crypto.js';

describe('requestSignBytes', () => {
  it('has correct length: idBytes + 8 + 4(inst) + comunitiID + dataBytes', () => {
    const id = 'abc';
    const time = new Uint8Array(8).fill(1);
    const data = new Uint8Array([10, 20]);
    const msg = requestSignBytes(id, time, 13, 'com', data);
    expect(msg.byteLength).toBe(3 + 8 + 4 + 3 + 2);
  });

  it('contains requestId at start and inst LE after time', () => {
    const id = 'hello';
    const time = new Uint8Array(8);
    const data = new Uint8Array(0);
    const msg = requestSignBytes(id, time, 0x14, '', data);
    const idBytes = new TextEncoder().encode(id);
    expect(msg.slice(0, 5)).toEqual(idBytes);
    // inst is 4 bytes LE immediately after the 8-byte time
    expect(new DataView(msg.buffer, msg.byteOffset).getUint32(5 + 8, true)).toBe(0x14);
  });
});

describe('responseSignBytes', () => {
  it('has correct length: id + 8 + data + 4 + errStr when errCode is non-zero', () => {
    const id = 'xy';
    const time = new Uint8Array(8);
    const data = new Uint8Array([1, 2, 3]);
    const errStr = 'oops';
    const msg = responseSignBytes(id, time, data, 5, errStr);
    expect(msg.byteLength).toBe(2 + 8 + 3 + 4 + 4);
  });

  it('omits ErrCode bytes when errCode is absent (matches Go SignResponseIndex)', () => {
    // Go only appends ErrCode when res.ErrCode != nil && *res.ErrCode != 0.
    const id = 'xy';
    const time = new Uint8Array(8);
    const data = new Uint8Array([1, 2, 3]);
    const msgNoErr = responseSignBytes(id, time, data);
    expect(msgNoErr.byteLength).toBe(2 + 8 + 3); // no ErrCode, no ErrStr

    const msgZeroCode = responseSignBytes(id, time, data, 0);
    expect(msgZeroCode.byteLength).toBe(2 + 8 + 3); // errCode=0 is not appended
  });
});

describe('signRequest / verifyResponse', () => {
  it('generates verifiable signature', () => {
    const { pub, priv } = generateSigningKey();
    const requestId = 'test-req-id';
    const data = new Uint8Array([1, 2, 3]);
    const { time, signature } = signRequest(priv, requestId, 13, 'com', data);

    // Rebuild signed bytes and verify manually
    const msg = requestSignBytes(requestId, time, 13, 'com', data);
    expect(verifyBytes(pub, msg, signature)).toBe(true);
  });

  it('rejects tampered data', () => {
    const { pub, priv } = generateSigningKey();
    const requestId = 'test-req-id';
    const data = new Uint8Array([1, 2, 3]);
    const { time, signature } = signRequest(priv, requestId, 13, 'com', data);

    const tampered = new Uint8Array([1, 2, 4]); // last byte changed
    const msg = requestSignBytes(requestId, time, 13, 'com', tampered);
    expect(verifyBytes(pub, msg, signature)).toBe(false);
  });

  it('rejects tampered inst (binding prevents handler redirection)', () => {
    const { pub, priv } = generateSigningKey();
    const requestId = 'test-req-id';
    const data = new Uint8Array([1, 2, 3]);
    const { time, signature } = signRequest(priv, requestId, 13, 'com', data);

    const msg = requestSignBytes(requestId, time, 14, 'com', data); // inst changed
    expect(verifyBytes(pub, msg, signature)).toBe(false);
  });

  it('rejects tampered comunitiID (binding prevents cross-comuniti replay)', () => {
    const { pub, priv } = generateSigningKey();
    const requestId = 'test-req-id';
    const data = new Uint8Array([1, 2, 3]);
    const { time, signature } = signRequest(priv, requestId, 13, 'com', data);

    const msg = requestSignBytes(requestId, time, 13, 'other', data); // comuniti changed
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
