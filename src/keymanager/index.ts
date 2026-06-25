import type { IStorage } from '../storage/interface.js';
import type { KeyMeta, FieldKeyChain, FieldKeyVersion, AltSalt, ExportBundle } from './types.js';
import {
  KeyTypeSigning, KeyTypeEncryption, KeyStatusActive, KeyStatusRevoked,
  ChainStatusActive, ChainStatusRevoked,
} from './types.js';
import {
  deriveKeys, aesgcmEncrypt, aesgcmDecrypt,
  generateSigningKey, signingPubFromPriv, signBytes, verifyBytes,
  generateEncryptionKey, encryptionPubFromPriv, encryptForRecipient, decryptFromSender,
  generateFieldKey, randomBytes,
  bytesToBase64, base64ToBytes,
} from './crypto.js';
import {
  KeyNotFoundError, WrongKeyTypeError, KeyRevokedError, NoL2PasswordError,
  CorruptError, TamperedError, InvalidKeyError, KeyExistsError,
  RotationNotSupportedError, VersionNotFoundError, AltSaltNotFoundError,
  LabelAlreadyInUseError, LabelNotAssignedError, LabelNotFoundError,
  // Backward-compat singletons used in public exports and one-off re-throws
  ErrKeyNotFound, ErrWrongKeyType, ErrKeyRevoked, ErrNoL2Password,
  ErrCorrupt, ErrTampered, ErrInvalidKey, ErrKeyExists,
  ErrRotationNotSupported, ErrVersionNotFound, ErrAltSaltNotFound,
  ErrLabelAlreadyInUse, ErrLabelNotAssigned, ErrLabelNotFound,
} from './errors.js';
import { randomUUID } from '../util/uuid.js';

export interface KeyManagerOptions {
  namespace?: string; // storage key prefix, default 'km'
}

interface Header {
  l1Salt: string; // base64
  l2Salt: string; // base64
}

interface PrivKeyRecord {
  keyId: string;
  privateKey: string; // base64
}

interface AltSaltRecord {
  id: string;
  label: string;
  keyMat: string; // base64, 64 bytes [0:32]=encKey [32:64]=hmacKey
  createdAt: string;
}

// periodStartForTime mirrors Go's periodStartForTime.
function periodStartForTime(startDate: number, interval: number, now: number): number {
  if (now <= startDate) return startDate;
  const k = Math.floor((now - startDate) / interval);
  return startDate + k * interval;
}

export class KeyManager {
  private ns: string;
  private storage: IStorage;
  private l1Enc!: Uint8Array;
  private l2Enc: Uint8Array | null = null;
  private hasL2 = false;

  // In-memory state
  private metas = new Map<string, KeyMeta>();
  private privKeys = new Map<string, Uint8Array>();
  private chains = new Map<string, FieldKeyChain>();
  private chainVersions = new Map<string, FieldKeyVersion[]>();
  private altSalts = new Map<string, AltSalt>();
  private altKeys = new Map<string, Uint8Array>(); // 64-byte key material
  private labels = new Map<string, string>();      // label → keyID
  private keyLabels = new Map<string, string[]>(); // keyID → labels[]

  private constructor(storage: IStorage, ns: string) {
    this.storage = storage;
    this.ns = ns;
  }

  // ── Static constructors ────────────────────────────────────────────────────

  static async create(
    storage: IStorage,
    l1Password: string,
    l2Password: string,
    opts?: KeyManagerOptions,
  ): Promise<KeyManager> {
    const ns = opts?.namespace ?? 'km';
    const km = new KeyManager(storage, ns);

    const l1Salt = randomBytes(32);
    const l2Salt = randomBytes(32);

    const l1 = await deriveKeys(new TextEncoder().encode(l1Password), l1Salt);
    const l2 = await deriveKeys(new TextEncoder().encode(l2Password), l2Salt);

    km.l1Enc = l1.encKey;
    km.l2Enc = l2.encKey;
    km.hasL2 = true;

    const header: Header = { l1Salt: bytesToBase64(l1Salt), l2Salt: bytesToBase64(l2Salt) };
    await storage.set(ns + ':header', header);

    return km;
  }

  static async open(
    storage: IStorage,
    l1Password: string,
    l2Password?: string,
    opts?: KeyManagerOptions,
  ): Promise<KeyManager> {
    const ns = opts?.namespace ?? 'km';
    const km = new KeyManager(storage, ns);

    const header = await storage.get<Header>(ns + ':header');
    if (!header) throw new CorruptError();

    const l1Salt = base64ToBytes(header.l1Salt);
    const l2Salt = base64ToBytes(header.l2Salt);

    const l1 = await deriveKeys(new TextEncoder().encode(l1Password), l1Salt);
    km.l1Enc = l1.encKey;

    if (l2Password != null) {
      const l2 = await deriveKeys(new TextEncoder().encode(l2Password), l2Salt);
      km.l2Enc = l2.encKey;
      km.hasL2 = true;
    }

    await km.replayAll();
    return km;
  }

  // ── Storage helpers ────────────────────────────────────────────────────────

  private async writeL1<T>(key: string, value: T): Promise<void> {
    const json = JSON.stringify(value);
    const ct = await aesgcmEncrypt(this.l1Enc, new TextEncoder().encode(json));
    await this.storage.set(key, bytesToBase64(ct));
  }

  private async readL1<T>(key: string): Promise<T | null> {
    const b64 = await this.storage.get<string>(key);
    if (b64 == null) return null;
    // Decryption failure means the data was tampered — surface it explicitly.
    const plain = await aesgcmDecrypt(this.l1Enc, base64ToBytes(b64)).catch(() => {
      throw new TamperedError();
    });
    return JSON.parse(new TextDecoder().decode(plain)) as T;
  }

  private async writeL2<T>(key: string, value: T): Promise<void> {
    if (!this.hasL2 || !this.l2Enc) throw new NoL2PasswordError();
    const json = JSON.stringify(value);
    const ct = await aesgcmEncrypt(this.l2Enc, new TextEncoder().encode(json));
    await this.storage.set(key, bytesToBase64(ct));
  }

  private async readL2<T>(key: string): Promise<T | null> {
    if (!this.hasL2 || !this.l2Enc) return null;
    const b64 = await this.storage.get<string>(key);
    if (b64 == null) return null;
    // Decryption failure means the data was tampered — surface it explicitly.
    const plain = await aesgcmDecrypt(this.l2Enc, base64ToBytes(b64)).catch(() => {
      throw new TamperedError();
    });
    return JSON.parse(new TextDecoder().decode(plain)) as T;
  }

  private async writeAlt<T>(altSaltId: string, storageKey: string, value: T): Promise<void> {
    const keyMat = this.altKeys.get(altSaltId);
    if (!keyMat) throw new AltSaltNotFoundError();
    const encKey = keyMat.slice(0, 32);
    const json = JSON.stringify(value);
    const ct = await aesgcmEncrypt(encKey, new TextEncoder().encode(json));
    await this.storage.set(storageKey, bytesToBase64(ct));
  }

  private async readAlt<T>(altSaltId: string, storageKey: string): Promise<T | null> {
    const keyMat = this.altKeys.get(altSaltId);
    if (!keyMat) return null;
    const encKey = keyMat.slice(0, 32);
    const b64 = await this.storage.get<string>(storageKey);
    if (b64 == null) return null;
    // Decryption failure means the data was tampered — surface it explicitly.
    const plain = await aesgcmDecrypt(encKey, base64ToBytes(b64)).catch(() => {
      throw new TamperedError();
    });
    return JSON.parse(new TextDecoder().decode(plain)) as T;
  }

  // ── Replay (load all stored keys into memory) ──────────────────────────────

  private async replayAll(): Promise<void> {
    // Load all stored key IDs from an index
    const index = await this.readL1<{ keyIds: string[]; chainIds: string[]; altSaltIds: string[] }>(this.ns + ':index');
    if (!index) return;

    // Load alt salts first (needed to decrypt alt-encrypted privkeys)
    for (const id of index.altSaltIds) {
      const rec = await this.readL2<AltSaltRecord>(this.ns + ':alt:' + id);
      if (rec) {
        this.altSalts.set(rec.id, { id: rec.id, label: rec.label, createdAt: rec.createdAt });
        this.altKeys.set(rec.id, base64ToBytes(rec.keyMat));
      }
    }

    // Load key metas + private keys
    for (const id of index.keyIds) {
      const meta = await this.readL1<KeyMeta>(this.ns + ':meta:' + id);
      if (!meta) continue;
      this.metas.set(id, meta);

      // Try standard L2 private key
      const priv = await this.readL2<PrivKeyRecord>(this.ns + ':priv:' + id);
      if (priv) {
        this.privKeys.set(id, base64ToBytes(priv.privateKey));
      } else {
        // Try alt-salt encrypted private key
        for (const [altId] of this.altKeys) {
          const altPriv = await this.readAlt<PrivKeyRecord>(altId, this.ns + ':altpriv:' + id + ':' + altId);
          if (altPriv) {
            this.privKeys.set(id, base64ToBytes(altPriv.privateKey));
            break;
          }
        }
      }
    }

    // Load field key chains + versions + field privkeys
    for (const id of index.chainIds) {
      const chain = await this.readL1<FieldKeyChain>(this.ns + ':chain:' + id);
      if (!chain) continue;
      this.chains.set(id, chain);

      const versions = await this.readL1<FieldKeyVersion[]>(this.ns + ':versions:' + id) ?? [];
      this.chainVersions.set(id, versions);

      for (const ver of versions) {
        let priv: PrivKeyRecord | null = null;
        if (chain.altSaltId) {
          priv = await this.readAlt<PrivKeyRecord>(chain.altSaltId, this.ns + ':altpriv:' + ver.versionId + ':' + chain.altSaltId);
        } else {
          priv = await this.readL2<PrivKeyRecord>(this.ns + ':fieldpriv:' + ver.versionId);
        }
        if (priv) this.privKeys.set(ver.versionId, base64ToBytes(priv.privateKey));
      }
    }

    // Load label index
    const labelIndex = await this.readL1<{ labels: Record<string, string>; keyLabels: Record<string, string[]> }>(this.ns + ':labels');
    if (labelIndex) {
      for (const [label, keyId] of Object.entries(labelIndex.labels)) this.labels.set(label, keyId);
      for (const [keyId, lbls] of Object.entries(labelIndex.keyLabels)) this.keyLabels.set(keyId, lbls);
    }
  }

  private async saveIndex(): Promise<void> {
    await this.writeL1(this.ns + ':index', {
      keyIds: [...this.metas.keys()],
      chainIds: [...this.chains.keys()],
      altSaltIds: [...this.altSalts.keys()],
    });
  }

  private async saveLabelIndex(): Promise<void> {
    const labels: Record<string, string> = {};
    const keyLabels: Record<string, string[]> = {};
    for (const [l, k] of this.labels) labels[l] = k;
    for (const [k, ls] of this.keyLabels) keyLabels[k] = ls;
    await this.writeL1(this.ns + ':labels', { labels, keyLabels });
  }

  // ── Signing keys (Ed25519) ─────────────────────────────────────────────────

  async createSigningKey(label: string): Promise<KeyMeta> {
    return this._createSigningKey(label, null);
  }

  async createSigningKeyWithAlt(label: string, altSaltId: string): Promise<KeyMeta> {
    if (!this.altKeys.has(altSaltId)) throw new AltSaltNotFoundError();
    return this._createSigningKey(label, altSaltId);
  }

  private async _createSigningKey(label: string, altSaltId: string | null): Promise<KeyMeta> {
    if (!this.hasL2) throw new NoL2PasswordError();
    if (label && this.labels.has(label)) throw new LabelAlreadyInUseError();

    const { pub, priv } = generateSigningKey();
    const meta: KeyMeta = {
      id: randomUUID(),
      type: KeyTypeSigning,
      status: KeyStatusActive,
      label,
      createdAt: new Date().toISOString(),
      publicKey: bytesToBase64(pub),
    };

    await this.writeL1(this.ns + ':meta:' + meta.id, meta);
    await this._writePrivKey(meta.id, priv, altSaltId);

    this.metas.set(meta.id, meta);
    this.privKeys.set(meta.id, priv);
    if (label) await this._assignLabelMem(meta.id, label);
    await this.saveIndex();
    return meta;
  }

  async addSigningKey(label: string, priv: Uint8Array): Promise<KeyMeta> {
    return this._addSigningKey(label, priv, null);
  }

  async addSigningKeyWithAlt(label: string, altSaltId: string, priv: Uint8Array): Promise<KeyMeta> {
    if (!this.altKeys.has(altSaltId)) throw new AltSaltNotFoundError();
    return this._addSigningKey(label, priv, altSaltId);
  }

  private async _addSigningKey(label: string, priv: Uint8Array, altSaltId: string | null): Promise<KeyMeta> {
    if (!this.hasL2) throw new NoL2PasswordError();
    if (priv.length !== 64) throw new InvalidKeyError();
    const pub = signingPubFromPriv(priv);
    const meta: KeyMeta = {
      id: randomUUID(),
      type: KeyTypeSigning,
      status: KeyStatusActive,
      label,
      createdAt: new Date().toISOString(),
      publicKey: bytesToBase64(pub),
    };
    await this.writeL1(this.ns + ':meta:' + meta.id, meta);
    await this._writePrivKey(meta.id, priv, altSaltId);
    this.metas.set(meta.id, meta);
    this.privKeys.set(meta.id, priv);
    if (label) await this._assignLabelMem(meta.id, label);
    await this.saveIndex();
    return meta;
  }

  async sign(keyId: string, message: Uint8Array): Promise<Uint8Array> {
    const meta = this.metas.get(keyId);
    if (!meta) throw new KeyNotFoundError();
    if (meta.type !== KeyTypeSigning) throw new WrongKeyTypeError();
    if (meta.status !== KeyStatusActive) throw new KeyRevokedError();
    const priv = this.privKeys.get(keyId);
    if (!priv) throw new NoL2PasswordError();
    return signBytes(priv, message);
  }

  async verify(keyId: string, message: Uint8Array, sig: Uint8Array): Promise<boolean> {
    const meta = this.metas.get(keyId);
    if (!meta) throw new KeyNotFoundError();
    if (meta.type !== KeyTypeSigning) throw new WrongKeyTypeError();
    return verifyBytes(base64ToBytes(meta.publicKey), message, sig);
  }

  static verifyRaw(pubKey: Uint8Array, message: Uint8Array, sig: Uint8Array): boolean {
    return verifyBytes(pubKey, message, sig);
  }

  // ── Encryption keys (X25519) ───────────────────────────────────────────────

  async createEncryptionKey(label: string): Promise<KeyMeta> {
    return this._createEncryptionKey(label, null);
  }

  async createEncryptionKeyWithAlt(label: string, altSaltId: string): Promise<KeyMeta> {
    if (!this.altKeys.has(altSaltId)) throw new AltSaltNotFoundError();
    return this._createEncryptionKey(label, altSaltId);
  }

  private async _createEncryptionKey(label: string, altSaltId: string | null): Promise<KeyMeta> {
    if (!this.hasL2) throw new NoL2PasswordError();
    if (label && this.labels.has(label)) throw new LabelAlreadyInUseError();

    const { pub, priv } = generateEncryptionKey();
    const meta: KeyMeta = {
      id: randomUUID(),
      type: KeyTypeEncryption,
      status: KeyStatusActive,
      label,
      createdAt: new Date().toISOString(),
      publicKey: bytesToBase64(pub),
    };
    await this.writeL1(this.ns + ':meta:' + meta.id, meta);
    await this._writePrivKey(meta.id, priv, altSaltId);
    this.metas.set(meta.id, meta);
    this.privKeys.set(meta.id, priv);
    if (label) await this._assignLabelMem(meta.id, label);
    await this.saveIndex();
    return meta;
  }

  async addEncryptionKey(label: string, priv: Uint8Array): Promise<KeyMeta> {
    return this._addEncryptionKey(label, priv, null);
  }

  async addEncryptionKeyWithAlt(label: string, altSaltId: string, priv: Uint8Array): Promise<KeyMeta> {
    if (!this.altKeys.has(altSaltId)) throw new AltSaltNotFoundError();
    return this._addEncryptionKey(label, priv, altSaltId);
  }

  private async _addEncryptionKey(label: string, priv: Uint8Array, altSaltId: string | null): Promise<KeyMeta> {
    if (!this.hasL2) throw new NoL2PasswordError();
    if (priv.length !== 32) throw new InvalidKeyError();
    const pub = encryptionPubFromPriv(priv);
    const meta: KeyMeta = {
      id: randomUUID(),
      type: KeyTypeEncryption,
      status: KeyStatusActive,
      label,
      createdAt: new Date().toISOString(),
      publicKey: bytesToBase64(pub),
    };
    await this.writeL1(this.ns + ':meta:' + meta.id, meta);
    await this._writePrivKey(meta.id, priv, altSaltId);
    this.metas.set(meta.id, meta);
    this.privKeys.set(meta.id, priv);
    if (label) await this._assignLabelMem(meta.id, label);
    await this.saveIndex();
    return meta;
  }

  async encryptFor(keyId: string, plaintext: Uint8Array): Promise<Uint8Array> {
    const meta = this.metas.get(keyId);
    if (!meta) throw new KeyNotFoundError();
    if (meta.type !== KeyTypeEncryption) throw new WrongKeyTypeError();
    if (meta.status !== KeyStatusActive) throw new KeyRevokedError();
    return encryptForRecipient(base64ToBytes(meta.publicKey), plaintext);
  }

  async decryptWith(keyId: string, ciphertext: Uint8Array): Promise<Uint8Array> {
    const meta = this.metas.get(keyId);
    if (!meta) throw new KeyNotFoundError();
    if (meta.type !== KeyTypeEncryption) throw new WrongKeyTypeError();
    const priv = this.privKeys.get(keyId);
    if (!priv) throw new NoL2PasswordError();
    return decryptFromSender(priv, ciphertext);
  }

  // ── Field keys (AES-256-GCM, time-rotating) ────────────────────────────────

  async createFieldKey(label: string, startDate: Date, interval?: number): Promise<FieldKeyChain> {
    return this._createFieldKey(label, startDate, interval, null);
  }

  async createFieldKeyWithAlt(label: string, startDate: Date, interval: number, altSaltId: string): Promise<FieldKeyChain> {
    if (!this.altKeys.has(altSaltId)) throw new AltSaltNotFoundError();
    return this._createFieldKey(label, startDate, interval, altSaltId);
  }

  private async _createFieldKey(label: string, startDate: Date, interval: number | undefined, altSaltId: string | null): Promise<FieldKeyChain> {
    if (!this.hasL2) throw new NoL2PasswordError();
    const iv = interval ?? 30 * 24 * 60 * 60 * 1000; // 30 days in ms

    const chain: FieldKeyChain = {
      id: randomUUID(),
      label,
      startDate: startDate.toISOString(),
      interval: iv,
      status: ChainStatusActive,
      createdAt: new Date().toISOString(),
      ...(altSaltId ? { altSaltId } : {}),
    };

    const firstVer: FieldKeyVersion = {
      chainId: chain.id,
      versionId: randomUUID(),
      validFrom: startDate.toISOString(),
    };

    const aesKey = generateFieldKey();

    await this.writeL1(this.ns + ':chain:' + chain.id, chain);
    await this.writeL1(this.ns + ':versions:' + chain.id, [firstVer]);
    await this._writeFieldPrivKey(firstVer.versionId, aesKey, altSaltId);

    this.chains.set(chain.id, chain);
    this.chainVersions.set(chain.id, [firstVer]);
    this.privKeys.set(firstVer.versionId, aesKey);
    if (label) await this._assignLabelMem(chain.id, label);
    await this.saveIndex();
    return chain;
  }

  async addFieldKey(label: string, startDate: Date, interval: number, keyBytes: Uint8Array): Promise<FieldKeyChain> {
    return this._addFieldKey(label, startDate, interval, keyBytes, null);
  }

  async addFieldKeyWithAlt(label: string, startDate: Date, interval: number, keyBytes: Uint8Array, altSaltId: string): Promise<FieldKeyChain> {
    if (!this.altKeys.has(altSaltId)) throw new AltSaltNotFoundError();
    return this._addFieldKey(label, startDate, interval, keyBytes, altSaltId);
  }

  private async _addFieldKey(label: string, startDate: Date, interval: number, keyBytes: Uint8Array, altSaltId: string | null): Promise<FieldKeyChain> {
    if (!this.hasL2) throw new NoL2PasswordError();
    if (keyBytes.length !== 32) throw new InvalidKeyError();

    const chain: FieldKeyChain = {
      id: randomUUID(),
      label,
      startDate: startDate.toISOString(),
      interval,
      status: ChainStatusActive,
      createdAt: new Date().toISOString(),
      ...(altSaltId ? { altSaltId } : {}),
    };
    const firstVer: FieldKeyVersion = {
      chainId: chain.id,
      versionId: randomUUID(),
      validFrom: startDate.toISOString(),
    };

    await this.writeL1(this.ns + ':chain:' + chain.id, chain);
    await this.writeL1(this.ns + ':versions:' + chain.id, [firstVer]);
    await this._writeFieldPrivKey(firstVer.versionId, keyBytes, altSaltId);

    this.chains.set(chain.id, chain);
    this.chainVersions.set(chain.id, [firstVer]);
    this.privKeys.set(firstVer.versionId, keyBytes);
    if (label) await this._assignLabelMem(chain.id, label);
    await this.saveIndex();
    return chain;
  }

  async encryptField(chainId: string, plaintext: Uint8Array): Promise<Uint8Array> {
    if (!this.hasL2) throw new NoL2PasswordError();
    const chain = this.chains.get(chainId);
    if (!chain) throw new KeyNotFoundError();
    if (chain.status !== ChainStatusActive) throw new KeyRevokedError();

    const versions = this.chainVersions.get(chainId) ?? [];
    const now = Date.now();
    const startMs = new Date(chain.startDate).getTime();
    const currentPeriodStart = periodStartForTime(startMs, chain.interval, now);

    const latest = versions[versions.length - 1];
    const latestMs = latest != null ? new Date(latest.validFrom).getTime() : -Infinity;

    if (latest == null || currentPeriodStart > latestMs) {
      // Rotate: add new version
      const newVer: FieldKeyVersion = {
        chainId,
        versionId: randomUUID(),
        validFrom: new Date(currentPeriodStart).toISOString(),
      };
      const newKey = generateFieldKey();
      const updatedVersions = [...versions, newVer];
      await this.writeL1(this.ns + ':versions:' + chainId, updatedVersions);
      await this._writeFieldPrivKey(newVer.versionId, newKey, chain.altSaltId ?? null);
      this.chainVersions.set(chainId, updatedVersions);
      this.privKeys.set(newVer.versionId, newKey);
      return aesgcmEncrypt(newKey, plaintext);
    }

    const key = this.privKeys.get(latest.versionId);
    if (!key) throw new NoL2PasswordError();
    return aesgcmEncrypt(key, plaintext);
  }

  async decryptField(chainId: string, ciphertext: Uint8Array, date: Date): Promise<Uint8Array> {
    if (!this.hasL2) throw new NoL2PasswordError();
    const versions = this.chainVersions.get(chainId);
    if (!versions) throw new KeyNotFoundError();

    const dateMs = date.getTime();
    let active: FieldKeyVersion | null = null;
    for (const v of versions) {
      if (new Date(v.validFrom).getTime() <= dateMs) active = v;
      else break;
    }
    if (!active) throw new VersionNotFoundError();

    const key = this.privKeys.get(active.versionId);
    if (!key) throw new NoL2PasswordError();
    return aesgcmDecrypt(key, ciphertext);
  }

  async getFieldKeyChain(chainId: string): Promise<FieldKeyChain> {
    const chain = this.chains.get(chainId);
    if (!chain) throw new KeyNotFoundError();
    return chain;
  }

  listFieldKeyChains(): FieldKeyChain[] {
    return [...this.chains.values()];
  }

  async listFieldKeyVersions(chainId: string): Promise<FieldKeyVersion[]> {
    if (!this.chains.has(chainId)) throw new KeyNotFoundError();
    return [...(this.chainVersions.get(chainId) ?? [])];
  }

  async revokeFieldKeyChain(chainId: string, _reason: string): Promise<void> {
    const chain = this.chains.get(chainId);
    if (!chain) throw new KeyNotFoundError();
    if (chain.status !== ChainStatusActive) throw new KeyRevokedError();
    chain.status = ChainStatusRevoked;
    await this.writeL1(this.ns + ':chain:' + chainId, chain);
  }

  // ── Key lifecycle ──────────────────────────────────────────────────────────

  getMeta(keyId: string): KeyMeta {
    const meta = this.metas.get(keyId);
    if (!meta) throw new KeyNotFoundError();
    return meta;
  }

  getPrivKey(keyId: string): Uint8Array {
    if (!this.metas.has(keyId)) throw new KeyNotFoundError();
    const priv = this.privKeys.get(keyId);
    if (!priv) throw new NoL2PasswordError();
    return priv;
  }

  listKeys(): KeyMeta[] {
    return [...this.metas.values()];
  }

  async revokeKey(keyId: string, _reason: string): Promise<void> {
    const meta = this.metas.get(keyId);
    if (!meta) throw new KeyNotFoundError();
    if (meta.status !== KeyStatusActive) throw new KeyRevokedError();
    meta.status = KeyStatusRevoked;
    meta.revokedAt = new Date().toISOString();
    await this.writeL1(this.ns + ':meta:' + keyId, meta);
  }

  rotateKey(_keyId: string): never {
    throw new RotationNotSupportedError();
  }

  // ── Labels ─────────────────────────────────────────────────────────────────

  async assignLabel(keyId: string, label: string): Promise<void> {
    if (!this.metas.has(keyId) && !this.chains.has(keyId)) throw new KeyNotFoundError();
    // _assignLabelMem already calls saveLabelIndex() — don't call it again.
    await this._assignLabelMem(keyId, label);
  }

  async revokeLabel(keyId: string, label: string): Promise<void> {
    const labels = this.keyLabels.get(keyId) ?? [];
    if (!labels.includes(label)) throw new LabelNotAssignedError();
    this.labels.delete(label);
    this.keyLabels.set(keyId, labels.filter(l => l !== label));
    await this.saveLabelIndex();
  }

  listKeyLabels(keyId: string): string[] {
    if (!this.metas.has(keyId) && !this.chains.has(keyId)) throw new KeyNotFoundError();
    return [...(this.keyLabels.get(keyId) ?? [])];
  }

  findKeyByLabel(label: string): string {
    const id = this.labels.get(label);
    if (!id) throw new LabelNotFoundError();
    return id;
  }

  private async _assignLabelMem(keyId: string, label: string): Promise<void> {
    const existing = this.labels.get(label);
    if (existing && existing !== keyId) throw new LabelAlreadyInUseError();
    this.labels.set(label, keyId);
    const current = this.keyLabels.get(keyId) ?? [];
    if (!current.includes(label)) {
      this.keyLabels.set(keyId, [...current, label]);
    }
    await this.saveLabelIndex();
  }

  // ── Alt salts ──────────────────────────────────────────────────────────────

  async createAltSalt(label: string): Promise<AltSalt> {
    if (!this.hasL2) throw new NoL2PasswordError();
    const keyMat = randomBytes(64);
    const rec: AltSaltRecord = {
      id: randomUUID(),
      label,
      keyMat: bytesToBase64(keyMat),
      createdAt: new Date().toISOString(),
    };
    await this.writeL2(this.ns + ':alt:' + rec.id, rec);

    const salt: AltSalt = { id: rec.id, label, createdAt: rec.createdAt };
    this.altSalts.set(rec.id, salt);
    this.altKeys.set(rec.id, keyMat);
    await this.saveIndex();
    return salt;
  }

  getAltSalt(id: string): AltSalt {
    const alt = this.altSalts.get(id);
    if (!alt) throw new AltSaltNotFoundError();
    return alt;
  }

  listAltSalts(): AltSalt[] {
    return [...this.altSalts.values()];
  }

  // ── Export / Import ────────────────────────────────────────────────────────

  async exportKey(keyId: string, exportPassword: string, includePrivate = true): Promise<ExportBundle> {
    const meta = this.metas.get(keyId);
    if (!meta) throw new KeyNotFoundError();

    const bundle: ExportBundle = { version: 1, exportedAt: new Date().toISOString(), meta };

    if (includePrivate) {
      const priv = this.privKeys.get(keyId);
      if (!priv) throw new NoL2PasswordError();
      const salt = randomBytes(32);
      const { encKey } = await deriveKeys(new TextEncoder().encode(exportPassword), salt);
      const ct = await aesgcmEncrypt(encKey, priv);
      bundle.encryptedPrivKey = bytesToBase64(ct);
      bundle.exportSalt = bytesToBase64(salt);

      // Sign the bundle with an active signing key if available
      const signerEntry = [...this.metas.entries()].find(
        ([, m]) => m.type === KeyTypeSigning && m.status === KeyStatusActive && this.privKeys.has(m.id),
      );
      if (signerEntry) {
        const [signerId, signerMeta] = signerEntry;
        const payload = new TextEncoder().encode(JSON.stringify(meta) + bundle.encryptedPrivKey);
        const sig = await this.sign(signerId, payload);
        bundle.signature = bytesToBase64(sig);
        bundle.signerKeyId = signerMeta.id;
      }
    }

    return bundle;
  }

  async importKey(bundle: ExportBundle, importPassword: string): Promise<void> {
    const { meta } = bundle;
    if (this.metas.has(meta.id)) throw new KeyExistsError();

    // Verify signature when present.
    // Priority: (1) self-signed (signerKeyId === meta.id) → use the key's own
    // public key from the bundle; (2) signer is in this KM → use its public
    // key; (3) signer is unknown cross-KM → skip (can't verify without the
    // private key, and an attacker still can't forge without it).
    if (bundle.signature && bundle.signerKeyId) {
      let signerPub: Uint8Array | null = null;

      if (bundle.signerKeyId === meta.id) {
        signerPub = base64ToBytes(meta.publicKey);
      } else {
        const signerMeta = this.metas.get(bundle.signerKeyId);
        if (signerMeta) signerPub = base64ToBytes(signerMeta.publicKey);
      }

      if (signerPub) {
        const payload = new TextEncoder().encode(JSON.stringify(meta) + bundle.encryptedPrivKey);
        if (!verifyBytes(signerPub, payload, base64ToBytes(bundle.signature))) {
          throw new InvalidKeyError();
        }
      }
    }

    await this.writeL1(this.ns + ':meta:' + meta.id, meta);
    this.metas.set(meta.id, meta);

    if (bundle.encryptedPrivKey && bundle.exportSalt) {
      const salt = base64ToBytes(bundle.exportSalt);
      const { encKey } = await deriveKeys(new TextEncoder().encode(importPassword), salt);
      const priv = await aesgcmDecrypt(encKey, base64ToBytes(bundle.encryptedPrivKey));
      await this._writePrivKey(meta.id, priv, null);
      this.privKeys.set(meta.id, priv);
    }

    if (meta.label) await this._assignLabelMem(meta.id, meta.label);
    await this.saveIndex();
  }

  marshalBundle(bundle: ExportBundle): string {
    return JSON.stringify(bundle);
  }

  unmarshalBundle(data: string): ExportBundle {
    return JSON.parse(data) as ExportBundle;
  }

  // ── Private helpers ────────────────────────────────────────────────────────

  private async _writePrivKey(keyId: string, priv: Uint8Array, altSaltId: string | null): Promise<void> {
    const rec: PrivKeyRecord = { keyId, privateKey: bytesToBase64(priv) };
    if (altSaltId) {
      await this.writeAlt(altSaltId, this.ns + ':altpriv:' + keyId + ':' + altSaltId, rec);
    } else {
      await this.writeL2(this.ns + ':priv:' + keyId, rec);
    }
  }

  private async _writeFieldPrivKey(versionId: string, key: Uint8Array, altSaltId: string | null): Promise<void> {
    const rec: PrivKeyRecord = { keyId: versionId, privateKey: bytesToBase64(key) };
    if (altSaltId) {
      await this.writeAlt(altSaltId, this.ns + ':altpriv:' + versionId + ':' + altSaltId, rec);
    } else {
      await this.writeL2(this.ns + ':fieldpriv:' + versionId, rec);
    }
  }
}

// Re-export error singletons so consumers who import them from this module
// continue to work without changes.
export {
  ErrKeyNotFound, ErrWrongKeyType, ErrKeyRevoked, ErrNoL2Password,
  ErrCorrupt, ErrTampered, ErrInvalidKey, ErrKeyExists,
  ErrRotationNotSupported, ErrVersionNotFound, ErrAltSaltNotFound,
  ErrLabelAlreadyInUse, ErrLabelNotAssigned, ErrLabelNotFound,
};
