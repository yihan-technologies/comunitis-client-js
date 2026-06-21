export const KeyTypeSigning = 1 as const;
export const KeyTypeEncryption = 2 as const;
export type KeyType = typeof KeyTypeSigning | typeof KeyTypeEncryption;

export const KeyStatusActive = 1 as const;
export const KeyStatusRevoked = 2 as const;
export type KeyStatus = typeof KeyStatusActive | typeof KeyStatusRevoked;

export const ChainStatusActive = 1 as const;
export const ChainStatusRevoked = 2 as const;
export type ChainStatus = typeof ChainStatusActive | typeof ChainStatusRevoked;

export interface KeyMeta {
  id: string;
  type: KeyType;
  status: KeyStatus;
  label: string;
  createdAt: string; // ISO 8601
  revokedAt?: string;
  publicKey: string; // base64
}

export interface FieldKeyChain {
  id: string;
  label: string;
  startDate: string; // ISO 8601
  interval: number;  // milliseconds
  status: ChainStatus;
  createdAt: string;
  altSaltId?: string;
}

export interface FieldKeyVersion {
  chainId: string;
  versionId: string;
  validFrom: string; // ISO 8601
}

export interface AltSalt {
  id: string;
  label: string;
  createdAt: string;
}

export interface ExportBundle {
  version: 1;
  exportedAt: string;
  meta: KeyMeta;
  encryptedPrivKey?: string; // base64, AES-GCM encrypted with export password
  exportSalt?: string;       // base64, 32 bytes Argon2id salt
  signature?: string;        // base64, Ed25519 over meta + encryptedPrivKey
  signerKeyId?: string;
}
