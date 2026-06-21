import { ed25519, x25519 } from '@noble/curves/ed25519.js';
import { sha512 } from '@noble/hashes/sha2.js';
import { randomBytes as nobleRandomBytes } from '@noble/hashes/utils.js';
import { argon2id } from 'hash-wasm';

// Argon2id params matching the Go keymanager exactly.
const ARGON2_TIME = 3;
const ARGON2_MEMORY = 65536; // 64 MB in KiB
const ARGON2_PARALLELISM = 4;
const ARGON2_KEY_LEN = 64; // 32 enc + 32 hmac

export async function deriveKeys(password: Uint8Array, salt: Uint8Array): Promise<{ encKey: Uint8Array; hmacKey: Uint8Array }> {
  const hex = await argon2id({
    password,
    salt,
    iterations: ARGON2_TIME,
    memorySize: ARGON2_MEMORY,
    parallelism: ARGON2_PARALLELISM,
    hashLength: ARGON2_KEY_LEN,
    outputType: 'hex',
  });
  const raw = hexToBytes(hex);
  return { encKey: raw.slice(0, 32), hmacKey: raw.slice(32, 64) };
}

// Ensure a Uint8Array has a plain ArrayBuffer for Web Crypto (avoids SharedArrayBuffer issues).
function toPlainBuffer(u: Uint8Array): ArrayBuffer {
  const buf = new ArrayBuffer(u.byteLength);
  new Uint8Array(buf).set(u);
  return buf;
}

// AES-256-GCM — nonce prepended: [12-byte nonce][ciphertext]
export async function aesgcmEncrypt(key: Uint8Array, plaintext: Uint8Array): Promise<Uint8Array> {
  const nonce = randomBytes(12);
  const cryptoKey = await crypto.subtle.importKey('raw', toPlainBuffer(key), 'AES-GCM', false, ['encrypt']);
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, cryptoKey, toPlainBuffer(plaintext));
  const result = new Uint8Array(12 + ct.byteLength);
  result.set(nonce, 0);
  result.set(new Uint8Array(ct), 12);
  return result;
}

export async function aesgcmDecrypt(key: Uint8Array, ciphertext: Uint8Array): Promise<Uint8Array> {
  if (ciphertext.length < 12) throw new Error('corrupt: ciphertext too short');
  const nonce = ciphertext.slice(0, 12);
  const ct = ciphertext.slice(12);
  const cryptoKey = await crypto.subtle.importKey('raw', toPlainBuffer(key), 'AES-GCM', false, ['decrypt']);
  const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: nonce }, cryptoKey, toPlainBuffer(ct));
  return new Uint8Array(plain);
}

export async function hmacSha256(key: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
  const cryptoKey = await crypto.subtle.importKey('raw', toPlainBuffer(key), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', cryptoKey, toPlainBuffer(data));
  return new Uint8Array(sig);
}

// Ed25519
// Stores private key as 64 bytes (seed[32] || public[32]) matching Go's ed25519.PrivateKey.
export function generateSigningKey(): { pub: Uint8Array; priv: Uint8Array } {
  const { secretKey, publicKey } = ed25519.keygen();
  const pub = publicKey instanceof Uint8Array ? publicKey : new Uint8Array(publicKey as ArrayBuffer);
  const seed = secretKey instanceof Uint8Array ? secretKey : new Uint8Array(secretKey as ArrayBuffer);
  const priv64 = new Uint8Array(64);
  priv64.set(seed, 0);
  priv64.set(pub, 32);
  return { pub, priv: priv64 };
}

export function signingPubFromPriv(priv64: Uint8Array): Uint8Array {
  return ed25519.getPublicKey(priv64.slice(0, 32));
}

export function signBytes(priv64: Uint8Array, message: Uint8Array): Uint8Array {
  // noble curves sign(message, secretKey) — secretKey is the 32-byte seed
  return ed25519.sign(message, priv64.slice(0, 32));
}

export function verifyBytes(pub: Uint8Array, message: Uint8Array, sig: Uint8Array): boolean {
  try {
    return ed25519.verify(sig, message, pub);
  } catch {
    return false;
  }
}

// X25519 ECDH
export function generateEncryptionKey(): { pub: Uint8Array; priv: Uint8Array } {
  const { secretKey, publicKey } = x25519.keygen();
  const priv = secretKey instanceof Uint8Array ? secretKey : new Uint8Array(secretKey as ArrayBuffer);
  const pub = publicKey instanceof Uint8Array ? publicKey : new Uint8Array(publicKey as ArrayBuffer);
  return { pub, priv };
}

export function encryptionPubFromPriv(priv: Uint8Array): Uint8Array {
  return x25519.getPublicKey(priv);
}

// Matches Go encryptForRecipient: [32-byte ephemeral pubkey][AES-GCM ciphertext]
// KDF: SHA-512(shared_secret)[0:32] as AES key
export async function encryptForRecipient(recipientPub: Uint8Array, plaintext: Uint8Array): Promise<Uint8Array> {
  const { secretKey: ephPriv, publicKey: ephPub } = x25519.keygen();
  const ephPrivBytes = ephPriv instanceof Uint8Array ? ephPriv : new Uint8Array(ephPriv as ArrayBuffer);
  const ephPubBytes = ephPub instanceof Uint8Array ? ephPub : new Uint8Array(ephPub as ArrayBuffer);
  const shared = x25519.getSharedSecret(ephPrivBytes, recipientPub);
  const h = sha512(shared);
  const aesKey = h.slice(0, 32);
  const ct = await aesgcmEncrypt(aesKey, plaintext);
  const out = new Uint8Array(32 + ct.length);
  out.set(ephPubBytes, 0);
  out.set(ct, 32);
  return out;
}

export async function decryptFromSender(recipientPriv: Uint8Array, ciphertext: Uint8Array): Promise<Uint8Array> {
  if (ciphertext.length < 32) throw new Error('corrupt: ciphertext too short');
  const ephPub = ciphertext.slice(0, 32);
  const ct = ciphertext.slice(32);
  const shared = x25519.getSharedSecret(recipientPriv, ephPub);
  const h = sha512(shared);
  const aesKey = h.slice(0, 32);
  return aesgcmDecrypt(aesKey, ct);
}

// AES-256 field key (32 random bytes)
export function generateFieldKey(): Uint8Array {
  return randomBytes(32);
}

export function randomBytes(n: number): Uint8Array {
  return nobleRandomBytes(n);
}

// Encoding utilities
export function hexToBytes(hex: string): Uint8Array {
  const result = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    result[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  }
  return result;
}

export function bytesToBase64(bytes: Uint8Array): string {
  // Loop instead of spread-into-args to avoid stack overflow for large arrays.
  let binary = '';
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]!);
  return btoa(binary);
}

export function base64ToBytes(b64: string): Uint8Array {
  return Uint8Array.from(atob(b64), c => c.charCodeAt(0));
}

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}
