/**
 * Parser for the Go keymanager binary file format (KMGR).
 *
 * Binary layout:
 *   [8 bytes]  Magic: 'K','M','G','R',0x01,0x00,0x00,0x00
 *   [header]   type(0)=1 | len(4 LE) | SHA-256(32) | JSON {"v":N,"l1s":"b64","l2s":"b64"}
 *   [entries]  type(1) | len(4 LE) | HMAC-SHA256(32) | AES-GCM encrypted payload
 *
 * Entry types relevant to import:
 *   0 = header (plaintext)
 *   1 = KeyMeta (L1-encrypted JSON)
 *   2 = PrivKey (L2-encrypted JSON {"key_id":"...","private_key":"b64"})
 */

import { deriveKeys, aesgcmDecrypt } from '../keymanager/crypto.js';

// Magic bytes: 'K','M','G','R',0x01,0x00,0x00,0x00
const KMGR_MAGIC = new Uint8Array([75, 77, 71, 82, 1, 0, 0, 0]);

const ENTRY_HEADER  = 0;
const ENTRY_KEYMETA = 1;
const ENTRY_PRIVKEY = 2;

interface KmgrHeader {
  v: number;
  l1s: string; // base64 L1 Argon2id salt
  l2s: string; // base64 L2 Argon2id salt
}

interface GoKeyMeta {
  id: string;
  type: number;   // 1=signing Ed25519, 2=encryption X25519
  status: number;
  label: string;
  created_at: string;
  public_key: string; // base64 raw public key bytes
}

interface GoPrivKeyRecord {
  key_id: string;
  private_key: string; // base64 raw private key bytes
}

export interface GoExportBundleData {
  privKey: Uint8Array;
  pubKey: Uint8Array;
  keyType: 1 | 2;
  label: string;
}

// Mirrors Go's deriveKey(): SHA-256(raw_password) → 32-byte key.
// main.go calls promptNewPassword() → deriveKey() before passing to keymanager.New,
// so the Argon2id input is SHA-256(typed_password), not the raw typed password.
async function prehashPassword(raw: string): Promise<Uint8Array> {
  const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(raw));
  return new Uint8Array(hash);
}

function fromBase64(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function readU32LE(buf: Uint8Array, offset: number): number {
  return (buf[offset]! | (buf[offset + 1]! << 8) | (buf[offset + 2]! << 16) | (buf[offset + 3]! << 24)) >>> 0;
}

/**
 * Parse and decrypt a Go keymanager binary export file (KMGR format).
 *
 * Both l1Password and l2Password are required to decrypt the private key.
 * l1Password alone decrypts only public key metadata.
 *
 * @throws if the file is not a valid KMGR file, the magic is wrong, or passwords fail.
 */
export async function parseGoExportBundle(
  data: Uint8Array,
  l1Password: string,
  l2Password: string,
): Promise<GoExportBundleData> {
  let offset = 0;

  // ── Magic ──────────────────────────────────────────────────────────────────

  if (data.length < 8) throw new Error('File too short to be a KMGR keystore');
  for (let i = 0; i < 8; i++) {
    if (data[i] !== KMGR_MAGIC[i]) throw new Error('Not a KMGR keystore file (magic mismatch)');
  }
  offset = 8;

  // ── Header entry ──────────────────────────────────────────────────────────
  // Format: [type=0 (1)] [len (4 LE)] [SHA-256 (32)] [JSON data (len)]

  if (data[offset] !== ENTRY_HEADER) throw new Error('Expected header entry at offset 8');
  offset += 1;

  const hdrLen = readU32LE(data, offset);
  offset += 4;
  offset += 32; // skip SHA-256 checksum (integrity checked by Argon2/AES-GCM on load)

  const hdrJson = new TextDecoder().decode(data.slice(offset, offset + hdrLen));
  offset += hdrLen;

  let hdr: KmgrHeader;
  try {
    hdr = JSON.parse(hdrJson) as KmgrHeader;
  } catch {
    throw new Error('Corrupt keystore header');
  }

  if (!hdr.l1s || !hdr.l2s) throw new Error('Keystore header missing Argon2 salts');

  // ── Derive L1 and L2 keys ─────────────────────────────────────────────────

  const l1Salt = fromBase64(hdr.l1s);
  const l2Salt = fromBase64(hdr.l2s);

  const [l1Pre, l2Pre] = await Promise.all([prehashPassword(l1Password), prehashPassword(l2Password)]);
  const [l1Keys, l2Keys] = await Promise.all([deriveKeys(l1Pre, l1Salt), deriveKeys(l2Pre, l2Salt)]);
  const l1Enc = l1Keys.encKey;
  const l2Enc = l2Keys.encKey;

  // ── Read entries ──────────────────────────────────────────────────────────
  // Format: [type (1)] [len (4 LE)] [HMAC-SHA256 (32)] [payload (len)]

  const metas: GoKeyMeta[] = [];
  const privs: GoPrivKeyRecord[] = [];

  while (offset < data.length) {
    if (offset + 1 + 4 + 32 > data.length) break;

    const entryType = data[offset];
    offset += 1;
    const payloadLen = readU32LE(data, offset);
    offset += 4;
    offset += 32; // HMAC (skip — AES-GCM provides authentication)

    if (offset + payloadLen > data.length) break;
    const payload = data.slice(offset, offset + payloadLen);
    offset += payloadLen;

    if (entryType === ENTRY_KEYMETA) {
      try {
        const plain = await aesgcmDecrypt(l1Enc, payload);
        const meta = JSON.parse(new TextDecoder().decode(plain)) as GoKeyMeta;
        metas.push(meta);
      } catch { /* wrong key or tampered — skip */ }
    } else if (entryType === ENTRY_PRIVKEY) {
      try {
        const plain = await aesgcmDecrypt(l2Enc, payload);
        const rec = JSON.parse(new TextDecoder().decode(plain)) as GoPrivKeyRecord;
        privs.push(rec);
      } catch { /* wrong key or tampered — skip */ }
    }
    // All other entry types are ignored for import purposes.
  }

  if (metas.length === 0) throw new Error('No key metadata found — check L1 password');
  if (privs.length === 0) throw new Error('No private key found — check L2 password');

  // Prefer signing key (type=1); fall back to first available.
  const meta = metas.find(m => m.type === 1) ?? metas[0]!;
  const priv = privs.find(p => p.key_id === meta.id) ?? privs[0]!;

  const privKey = fromBase64(priv.private_key);
  const pubKey = fromBase64(meta.public_key);

  return { privKey, pubKey, keyType: (meta.type === 2 ? 2 : 1) as 1 | 2, label: meta.label || '' };
}

/**
 * Like parseGoExportBundle but returns ALL keys found in the file.
 * Each entry pairs a GoKeyMeta with its matching private key record.
 * Keys whose private key is missing from the file are skipped.
 */
export async function parseGoExportBundleAll(
  data: Uint8Array,
  l1Password: string,
  l2Password: string,
): Promise<GoExportBundleData[]> {
  let offset = 0;

  if (data.length < 8) throw new Error('File too short to be a KMGR keystore');
  for (let i = 0; i < 8; i++) {
    if (data[i] !== KMGR_MAGIC[i]) throw new Error('Not a KMGR keystore file (magic mismatch)');
  }
  offset = 8;

  if (data[offset] !== ENTRY_HEADER) throw new Error('Expected header entry at offset 8');
  offset += 1;

  const hdrLen = readU32LE(data, offset);
  offset += 4;
  offset += 32;

  const hdrJson = new TextDecoder().decode(data.slice(offset, offset + hdrLen));
  offset += hdrLen;

  let hdr: KmgrHeader;
  try {
    hdr = JSON.parse(hdrJson) as KmgrHeader;
  } catch {
    throw new Error('Corrupt keystore header');
  }

  if (!hdr.l1s || !hdr.l2s) throw new Error('Keystore header missing Argon2 salts');

  const l1Salt = fromBase64(hdr.l1s);
  const l2Salt = fromBase64(hdr.l2s);

  const [l1Pre, l2Pre] = await Promise.all([prehashPassword(l1Password), prehashPassword(l2Password)]);
  const [l1Keys, l2Keys] = await Promise.all([deriveKeys(l1Pre, l1Salt), deriveKeys(l2Pre, l2Salt)]);
  const l1Enc = l1Keys.encKey;
  const l2Enc = l2Keys.encKey;

  const metas: GoKeyMeta[] = [];
  const privs: GoPrivKeyRecord[] = [];

  while (offset < data.length) {
    if (offset + 1 + 4 + 32 > data.length) break;

    const entryType = data[offset];
    offset += 1;
    const payloadLen = readU32LE(data, offset);
    offset += 4;
    offset += 32;

    if (offset + payloadLen > data.length) break;
    const payload = data.slice(offset, offset + payloadLen);
    offset += payloadLen;

    if (entryType === ENTRY_KEYMETA) {
      try {
        const plain = await aesgcmDecrypt(l1Enc, payload);
        metas.push(JSON.parse(new TextDecoder().decode(plain)) as GoKeyMeta);
      } catch { /* skip */ }
    } else if (entryType === ENTRY_PRIVKEY) {
      try {
        const plain = await aesgcmDecrypt(l2Enc, payload);
        privs.push(JSON.parse(new TextDecoder().decode(plain)) as GoPrivKeyRecord);
      } catch { /* skip */ }
    }
  }

  if (metas.length === 0) throw new Error('No key metadata found — check L1 password');
  if (privs.length === 0) throw new Error('No private key found — check L2 password');

  const results: GoExportBundleData[] = [];
  for (const meta of metas) {
    const priv = privs.find(p => p.key_id === meta.id);
    if (!priv) continue;
    results.push({
      privKey: fromBase64(priv.private_key),
      pubKey: fromBase64(meta.public_key),
      keyType: (meta.type === 2 ? 2 : 1) as 1 | 2,
      label: meta.label || '',
    });
  }

  if (results.length === 0) throw new Error('No keys with matching private key found in bundle');
  return results;
}
