import { describe, it, expect, beforeEach } from 'vitest';
import { KeyManager } from './index.js';
import type { IStorage } from '../storage/interface.js';
import {
  KeyTypeSigning, KeyTypeEncryption,
  KeyStatusActive, KeyStatusRevoked,
  ChainStatusActive, ChainStatusRevoked,
} from './types.js';
import {
  ErrKeyNotFound, ErrWrongKeyType, ErrKeyRevoked, ErrNoL2Password,
  ErrInvalidKey, ErrKeyExists, ErrLabelAlreadyInUse, ErrLabelNotFound,
  ErrLabelNotAssigned, ErrAltSaltNotFound,
} from './errors.js';

class MemStorage implements IStorage {
  private store = new Map<string, unknown>();
  async get<T = unknown>(key: string): Promise<T | null> {
    return (this.store.get(key) as T) ?? null;
  }
  async set<T = unknown>(key: string, value: T): Promise<void> {
    this.store.set(key, value);
  }
  async delete(key: string): Promise<void> {
    this.store.delete(key);
  }
  async has(key: string): Promise<boolean> {
    return this.store.has(key);
  }
}

const L1 = 'password1';
const L2 = 'password2';

async function freshKM(): Promise<{ km: KeyManager; store: MemStorage }> {
  const store = new MemStorage();
  const km = await KeyManager.create(store, L1, L2);
  return { km, store };
}

// ── Signing keys ─────────────────────────────────────────────────────────────

describe('KeyManager — signing keys', () => {
  it('createSigningKey returns active signing meta', async () => {
    const { km } = await freshKM();
    const meta = await km.createSigningKey('mykey');
    expect(meta.type).toBe(KeyTypeSigning);
    expect(meta.status).toBe(KeyStatusActive);
    expect(meta.label).toBe('mykey');
    expect(meta.publicKey).toBeTruthy();
    expect(meta.id).toBeTruthy();
  });

  it('getMeta retrieves meta by id', async () => {
    const { km } = await freshKM();
    const meta = await km.createSigningKey('k');
    expect(km.getMeta(meta.id)).toEqual(meta);
  });

  it('getMeta throws ErrKeyNotFound for unknown id', async () => {
    const { km } = await freshKM();
    expect(() => km.getMeta('unknown')).toThrow(ErrKeyNotFound.message);
  });

  it('sign / verify roundtrip', async () => {
    const { km } = await freshKM();
    const meta = await km.createSigningKey('signer');
    const msg = new TextEncoder().encode('hello world');
    const sig = await km.sign(meta.id, msg);
    expect(await km.verify(meta.id, msg, sig)).toBe(true);
  });

  it('verify rejects tampered message', async () => {
    const { km } = await freshKM();
    const meta = await km.createSigningKey('s');
    const msg = new TextEncoder().encode('data');
    const sig = await km.sign(meta.id, msg);
    msg[0] ^= 0xff;
    expect(await km.verify(meta.id, msg, sig)).toBe(false);
  });

  it('sign throws ErrWrongKeyType for encryption key', async () => {
    const { km } = await freshKM();
    const meta = await km.createEncryptionKey('enc');
    await expect(km.sign(meta.id, new Uint8Array(1))).rejects.toThrow(ErrWrongKeyType.message);
  });

  it('revokeKey marks status revoked and sets revokedAt', async () => {
    const { km } = await freshKM();
    const meta = await km.createSigningKey('r');
    await km.revokeKey(meta.id, 'expired');
    const updated = km.getMeta(meta.id);
    expect(updated.status).toBe(KeyStatusRevoked);
    expect(updated.revokedAt).toBeTruthy();
  });

  it('sign throws ErrKeyRevoked after revocation', async () => {
    const { km } = await freshKM();
    const meta = await km.createSigningKey('r');
    await km.revokeKey(meta.id, 'x');
    await expect(km.sign(meta.id, new Uint8Array(1))).rejects.toThrow(ErrKeyRevoked.message);
  });

  it('listKeys includes created key', async () => {
    const { km } = await freshKM();
    const meta = await km.createSigningKey('l');
    expect(km.listKeys().some(m => m.id === meta.id)).toBe(true);
  });

  it('addSigningKey rejects bad priv length', async () => {
    const { km } = await freshKM();
    await expect(km.addSigningKey('x', new Uint8Array(32))).rejects.toThrow(ErrInvalidKey.message);
  });
});

// ── Encryption keys ───────────────────────────────────────────────────────────

describe('KeyManager — encryption keys', () => {
  it('createEncryptionKey returns active encryption meta', async () => {
    const { km } = await freshKM();
    const meta = await km.createEncryptionKey('enc');
    expect(meta.type).toBe(KeyTypeEncryption);
    expect(meta.status).toBe(KeyStatusActive);
  });

  it('encryptFor / decryptWith roundtrip', async () => {
    const { km } = await freshKM();
    const meta = await km.createEncryptionKey('enc');
    const plain = new TextEncoder().encode('secret');
    const ct = await km.encryptFor(meta.id, plain);
    const pt = await km.decryptWith(meta.id, ct);
    expect(pt).toEqual(plain);
  });

  it('encryptFor throws ErrWrongKeyType for signing key', async () => {
    const { km } = await freshKM();
    const meta = await km.createSigningKey('s');
    await expect(km.encryptFor(meta.id, new Uint8Array(1))).rejects.toThrow(ErrWrongKeyType.message);
  });

  it('encryptFor throws ErrKeyRevoked after revocation', async () => {
    const { km } = await freshKM();
    const meta = await km.createEncryptionKey('e');
    await km.revokeKey(meta.id, 'x');
    await expect(km.encryptFor(meta.id, new Uint8Array(1))).rejects.toThrow(ErrKeyRevoked.message);
  });

  it('addEncryptionKey rejects bad priv length', async () => {
    const { km } = await freshKM();
    await expect(km.addEncryptionKey('x', new Uint8Array(64))).rejects.toThrow(ErrInvalidKey.message);
  });
});

// ── Field keys ────────────────────────────────────────────────────────────────

describe('KeyManager — field keys', () => {
  it('createFieldKey returns active chain', async () => {
    const { km } = await freshKM();
    const start = new Date();
    const chain = await km.createFieldKey('fk', start);
    expect(chain.status).toBe(ChainStatusActive);
    expect(chain.label).toBe('fk');
  });

  it('encryptField / decryptField roundtrip', async () => {
    const { km } = await freshKM();
    const start = new Date(Date.now() - 1000);
    const chain = await km.createFieldKey('fk', start, 30 * 24 * 3600 * 1000);
    const plain = new TextEncoder().encode('field value');
    const ct = await km.encryptField(chain.id, plain);
    const pt = await km.decryptField(chain.id, ct, new Date());
    expect(pt).toEqual(plain);
  });

  it('decryptField with now date picks correct rotation period', async () => {
    const { km } = await freshKM();
    // Start in the past so encryptField always rotates to a current-period key
    const start = new Date('2020-01-01T00:00:00Z');
    const chain = await km.createFieldKey('fk', start, 365 * 24 * 3600 * 1000);

    const now = new Date();
    const plain = new TextEncoder().encode('current value');
    const ct = await km.encryptField(chain.id, plain);

    // Decrypt with now — same period as encryption
    const pt = await km.decryptField(chain.id, ct, now);
    expect(pt).toEqual(plain);
  });

  it('revokeFieldKeyChain marks chain revoked', async () => {
    const { km } = await freshKM();
    const chain = await km.createFieldKey('fk', new Date());
    await km.revokeFieldKeyChain(chain.id, 'expired');
    const updated = await km.getFieldKeyChain(chain.id);
    expect(updated.status).toBe(ChainStatusRevoked);
  });

  it('encryptField throws ErrKeyRevoked for revoked chain', async () => {
    const { km } = await freshKM();
    const chain = await km.createFieldKey('fk', new Date());
    await km.revokeFieldKeyChain(chain.id, 'x');
    await expect(km.encryptField(chain.id, new Uint8Array(1))).rejects.toThrow(ErrKeyRevoked.message);
  });

  it('listFieldKeyChains includes created chain', async () => {
    const { km } = await freshKM();
    const chain = await km.createFieldKey('fc', new Date());
    expect(km.listFieldKeyChains().some(c => c.id === chain.id)).toBe(true);
  });

  it('listFieldKeyVersions returns versions for chain', async () => {
    const { km } = await freshKM();
    const chain = await km.createFieldKey('fk', new Date());
    const versions = await km.listFieldKeyVersions(chain.id);
    expect(versions.length).toBeGreaterThanOrEqual(1);
    expect(versions[0]!.chainId).toBe(chain.id);
  });
});

// ── Labels ────────────────────────────────────────────────────────────────────

describe('KeyManager — labels', () => {
  it('findKeyByLabel returns the key id', async () => {
    const { km } = await freshKM();
    const meta = await km.createSigningKey('myLabel');
    expect(km.findKeyByLabel('myLabel')).toBe(meta.id);
  });

  it('findKeyByLabel throws ErrLabelNotFound for unknown label', async () => {
    const { km } = await freshKM();
    expect(() => km.findKeyByLabel('nope')).toThrow(ErrLabelNotFound.message);
  });

  it('assignLabel adds label to key', async () => {
    const { km } = await freshKM();
    const meta = await km.createSigningKey('');
    await km.assignLabel(meta.id, 'extra');
    expect(km.findKeyByLabel('extra')).toBe(meta.id);
  });

  it('assignLabel throws ErrLabelAlreadyInUse when assigned to different key', async () => {
    const { km } = await freshKM();
    const a = await km.createSigningKey('a');
    const b = await km.createSigningKey('b');
    await expect(km.assignLabel(b.id, 'a')).rejects.toThrow(ErrLabelAlreadyInUse.message);
  });

  it('revokeLabel removes label mapping', async () => {
    const { km } = await freshKM();
    const meta = await km.createSigningKey('rl');
    await km.revokeLabel(meta.id, 'rl');
    expect(() => km.findKeyByLabel('rl')).toThrow(ErrLabelNotFound.message);
  });

  it('revokeLabel throws ErrLabelNotAssigned for label not on key', async () => {
    const { km } = await freshKM();
    const meta = await km.createSigningKey('');
    await expect(km.revokeLabel(meta.id, 'notassigned')).rejects.toThrow(ErrLabelNotAssigned.message);
  });

  it('listKeyLabels returns all labels for a key', async () => {
    const { km } = await freshKM();
    const meta = await km.createSigningKey('first');
    await km.assignLabel(meta.id, 'second');
    const labels = km.listKeyLabels(meta.id);
    expect(labels).toContain('first');
    expect(labels).toContain('second');
  });
});

// ── Alt salts ─────────────────────────────────────────────────────────────────

describe('KeyManager — alt salts', () => {
  it('createAltSalt returns a salt with id', async () => {
    const { km } = await freshKM();
    const salt = await km.createAltSalt('my-salt');
    expect(salt.id).toBeTruthy();
    expect(salt.label).toBe('my-salt');
  });

  it('getAltSalt retrieves by id', async () => {
    const { km } = await freshKM();
    const salt = await km.createAltSalt('s');
    expect(km.getAltSalt(salt.id)).toEqual(salt);
  });

  it('getAltSalt throws ErrAltSaltNotFound for unknown id', async () => {
    const { km } = await freshKM();
    expect(() => km.getAltSalt('nope')).toThrow(ErrAltSaltNotFound.message);
  });

  it('listAltSalts includes created salt', async () => {
    const { km } = await freshKM();
    const salt = await km.createAltSalt('x');
    expect(km.listAltSalts().some(s => s.id === salt.id)).toBe(true);
  });

  it('createSigningKeyWithAlt uses alt salt', async () => {
    const { km } = await freshKM();
    const salt = await km.createAltSalt('alt');
    const meta = await km.createSigningKeyWithAlt('altkey', salt.id);
    expect(meta.type).toBe(KeyTypeSigning);
  });

  it('createSigningKeyWithAlt throws ErrAltSaltNotFound for unknown salt', async () => {
    const { km } = await freshKM();
    await expect(km.createSigningKeyWithAlt('x', 'bad-id')).rejects.toThrow(ErrAltSaltNotFound.message);
  });
});

// ── Export / Import ───────────────────────────────────────────────────────────

describe('KeyManager — export / import', () => {
  it('exportKey includes encrypted private key', async () => {
    const { km } = await freshKM();
    const meta = await km.createSigningKey('exp');
    const bundle = await km.exportKey(meta.id, 'export-pass');
    expect(bundle.encryptedPrivKey).toBeTruthy();
    expect(bundle.exportSalt).toBeTruthy();
    expect(bundle.meta.id).toBe(meta.id);
  });

  it('importKey restores key and allows signing', async () => {
    const { km: src } = await freshKM();
    const meta = await src.createSigningKey('src');
    const bundle = await src.exportKey(meta.id, 'pass');
    const json = src.marshalBundle(bundle);

    const { km: dst } = await freshKM();
    const parsed = dst.unmarshalBundle(json);
    await dst.importKey(parsed, 'pass');

    // Can sign with imported key
    const msg = new TextEncoder().encode('hello');
    const sig = await dst.sign(meta.id, msg);
    expect(await dst.verify(meta.id, msg, sig)).toBe(true);
  });

  it('importKey throws ErrKeyExists if key already imported', async () => {
    const { km } = await freshKM();
    const meta = await km.createSigningKey('dup');
    const bundle = await km.exportKey(meta.id, 'p');
    await expect(km.importKey(bundle, 'p')).rejects.toThrow(ErrKeyExists.message);
  });

  it('exportKey without private key omits encryptedPrivKey', async () => {
    const { km } = await freshKM();
    const meta = await km.createSigningKey('pub-only');
    const bundle = await km.exportKey(meta.id, 'pass', false);
    expect(bundle.encryptedPrivKey).toBeUndefined();
  });
});

// ── Persistence (open) ───────────────────────────────────────────────────────

describe('KeyManager — persistence via open()', () => {
  it('reopened km can sign with persisted key', async () => {
    const store = new MemStorage();
    const km1 = await KeyManager.create(store, L1, L2);
    const meta = await km1.createSigningKey('persist');
    const msg = new TextEncoder().encode('persistent');
    const sig = await km1.sign(meta.id, msg);

    const km2 = await KeyManager.open(store, L1, L2);
    expect(km2.getMeta(meta.id).id).toBe(meta.id);
    expect(await km2.verify(meta.id, msg, sig)).toBe(true);
    expect(await km2.sign(meta.id, msg)).toBeTruthy();
  });

  it('reopened km without L2 cannot sign but can verify', async () => {
    const store = new MemStorage();
    const km1 = await KeyManager.create(store, L1, L2);
    const meta = await km1.createSigningKey('nol2');
    const msg = new TextEncoder().encode('test');
    const sig = await km1.sign(meta.id, msg);

    const km2 = await KeyManager.open(store, L1); // no L2
    expect(await km2.verify(meta.id, msg, sig)).toBe(true);
    await expect(km2.sign(meta.id, msg)).rejects.toThrow(ErrNoL2Password.message);
  });

  it('reopened km restores labels', async () => {
    const store = new MemStorage();
    const km1 = await KeyManager.create(store, L1, L2);
    const meta = await km1.createSigningKey('labelled');

    const km2 = await KeyManager.open(store, L1, L2);
    expect(km2.findKeyByLabel('labelled')).toBe(meta.id);
  });

  it('reopened km can decrypt persisted field key', async () => {
    const store = new MemStorage();
    const km1 = await KeyManager.create(store, L1, L2);
    const start = new Date(Date.now() - 1000);
    const chain = await km1.createFieldKey('fk', start, 30 * 24 * 3600 * 1000);
    const plain = new TextEncoder().encode('persisted field');
    const ct = await km1.encryptField(chain.id, plain);

    const km2 = await KeyManager.open(store, L1, L2);
    const pt = await km2.decryptField(chain.id, ct, new Date());
    expect(pt).toEqual(plain);
  });
});

// ── No-L2 guard ───────────────────────────────────────────────────────────────

describe('KeyManager — L2 guards', () => {
  it('createSigningKey throws ErrNoL2Password when opened without L2', async () => {
    const store = new MemStorage();
    await KeyManager.create(store, L1, L2);
    const km = await KeyManager.open(store, L1); // no L2
    await expect(km.createSigningKey('x')).rejects.toThrow(ErrNoL2Password.message);
  });
});
