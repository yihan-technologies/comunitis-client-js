import { describe, it, expect } from 'vitest';
import {
  deriveKeys,
  aesgcmEncrypt, aesgcmDecrypt,
  generateSigningKey, signingPubFromPriv, signBytes, verifyBytes,
  generateEncryptionKey, encryptionPubFromPriv, encryptForRecipient, decryptFromSender,
  generateFieldKey,
  bytesToBase64, base64ToBytes,
  bytesToHex, hexToBytes,
  randomBytes,
} from './crypto.js';

describe('deriveKeys', () => {
  it('returns 32-byte enc and hmac keys', async () => {
    const { encKey, hmacKey } = await deriveKeys(
      new TextEncoder().encode('password'),
      randomBytes(32),
    );
    expect(encKey.byteLength).toBe(32);
    expect(hmacKey.byteLength).toBe(32);
  });

  it('is deterministic for same password+salt', async () => {
    const salt = randomBytes(32);
    const pass = new TextEncoder().encode('hello');
    const a = await deriveKeys(pass, salt);
    const b = await deriveKeys(pass, salt);
    expect(a.encKey).toEqual(b.encKey);
    expect(a.hmacKey).toEqual(b.hmacKey);
  });

  it('differs for different salts', async () => {
    const pass = new TextEncoder().encode('same');
    const a = await deriveKeys(pass, randomBytes(32));
    const b = await deriveKeys(pass, randomBytes(32));
    expect(a.encKey).not.toEqual(b.encKey);
  });
});

describe('aesgcmEncrypt / aesgcmDecrypt', () => {
  it('roundtrips plaintext', async () => {
    const key = randomBytes(32);
    const plain = new TextEncoder().encode('hello world');
    const ct = await aesgcmEncrypt(key, plain);
    const pt = await aesgcmDecrypt(key, ct);
    expect(pt).toEqual(plain);
  });

  it('prepends 12-byte nonce', async () => {
    const key = randomBytes(32);
    const plain = new Uint8Array(0);
    const ct = await aesgcmEncrypt(key, plain);
    // AES-GCM: 12-byte nonce + 16-byte tag + 0-byte plaintext = 28 bytes
    expect(ct.byteLength).toBe(12 + 16);
  });

  it('rejects wrong key', async () => {
    const key1 = randomBytes(32);
    const key2 = randomBytes(32);
    const ct = await aesgcmEncrypt(key1, new TextEncoder().encode('secret'));
    await expect(aesgcmDecrypt(key2, ct)).rejects.toThrow();
  });

  it('rejects truncated ciphertext', async () => {
    await expect(aesgcmDecrypt(randomBytes(32), new Uint8Array(5))).rejects.toThrow('corrupt');
  });
});

describe('Ed25519 signing', () => {
  it('generateSigningKey returns 32-byte pub and 64-byte priv', () => {
    const { pub, priv } = generateSigningKey();
    expect(pub.byteLength).toBe(32);
    expect(priv.byteLength).toBe(64);
  });

  it('priv[32:64] == pub', () => {
    const { pub, priv } = generateSigningKey();
    expect(priv.slice(32)).toEqual(pub);
  });

  it('signingPubFromPriv matches pub', () => {
    const { pub, priv } = generateSigningKey();
    expect(signingPubFromPriv(priv)).toEqual(pub);
  });

  it('sign / verify roundtrip', () => {
    const { pub, priv } = generateSigningKey();
    const msg = new TextEncoder().encode('test message');
    const sig = signBytes(priv, msg);
    expect(verifyBytes(pub, msg, sig)).toBe(true);
  });

  it('rejects tampered message', () => {
    const { pub, priv } = generateSigningKey();
    const msg = new TextEncoder().encode('test message');
    const sig = signBytes(priv, msg);
    msg[0] ^= 0xff;
    expect(verifyBytes(pub, msg, sig)).toBe(false);
  });

  it('rejects wrong public key', () => {
    const { pub: wrongPub } = generateSigningKey();
    const { priv } = generateSigningKey();
    const msg = new TextEncoder().encode('test');
    const sig = signBytes(priv, msg);
    expect(verifyBytes(wrongPub, msg, sig)).toBe(false);
  });
});

describe('X25519 encryption', () => {
  it('generateEncryptionKey returns 32-byte keys', () => {
    const { pub, priv } = generateEncryptionKey();
    expect(pub.byteLength).toBe(32);
    expect(priv.byteLength).toBe(32);
  });

  it('encryptionPubFromPriv matches pub', () => {
    const { pub, priv } = generateEncryptionKey();
    expect(encryptionPubFromPriv(priv)).toEqual(pub);
  });

  it('encryptForRecipient / decryptFromSender roundtrip', async () => {
    const { pub, priv } = generateEncryptionKey();
    const plain = new TextEncoder().encode('secret data');
    const ct = await encryptForRecipient(pub, plain);
    const pt = await decryptFromSender(priv, ct);
    expect(pt).toEqual(plain);
  });

  it('ciphertext starts with 32-byte ephemeral pubkey', async () => {
    const { pub } = generateEncryptionKey();
    const ct = await encryptForRecipient(pub, new Uint8Array(0));
    // 32 (ephPub) + 12 (nonce) + 0 (plain) + 16 (tag) = 60
    expect(ct.byteLength).toBe(60);
  });

  it('rejects wrong private key', async () => {
    const { pub } = generateEncryptionKey();
    const { priv: wrongPriv } = generateEncryptionKey();
    const ct = await encryptForRecipient(pub, new TextEncoder().encode('test'));
    await expect(decryptFromSender(wrongPriv, ct)).rejects.toThrow();
  });
});

describe('generateFieldKey', () => {
  it('returns 32 bytes', () => {
    expect(generateFieldKey().byteLength).toBe(32);
  });

  it('is random', () => {
    expect(generateFieldKey()).not.toEqual(generateFieldKey());
  });
});

describe('base64 encoding', () => {
  it('roundtrips bytes', () => {
    const bytes = randomBytes(64);
    expect(base64ToBytes(bytesToBase64(bytes))).toEqual(bytes);
  });

  it('known value', () => {
    const bytes = new Uint8Array([0, 1, 255]);
    expect(bytesToBase64(bytes)).toBe('AAH/');
    expect(base64ToBytes('AAH/')).toEqual(bytes);
  });
});

describe('hex encoding', () => {
  it('roundtrips bytes', () => {
    const bytes = randomBytes(32);
    expect(hexToBytes(bytesToHex(bytes))).toEqual(bytes);
  });
});
