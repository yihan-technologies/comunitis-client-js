export { ComunitisClient } from './client/index.js';
export type { ClientConfig, RequestOptions } from './client/types.js';

export { KeyManager } from './keymanager/index.js';
export type { KeyManagerOptions } from './keymanager/index.js';
export type { KeyMeta, FieldKeyChain, FieldKeyVersion, AltSalt, ExportBundle } from './keymanager/types.js';
export { KeyTypeSigning, KeyTypeEncryption, KeyStatusActive, KeyStatusRevoked, ChainStatusActive, ChainStatusRevoked } from './keymanager/types.js';

export type { IStorage, StorageOptions } from './storage/interface.js';

export { parseServerKeyFile } from './keyfile/parse.js';
export type { ServerKeyFileData } from './keyfile/parse.js';
export { parseGoExportBundle } from './keyfile/go-bundle.js';
export type { GoExportBundleData } from './keyfile/go-bundle.js';

export { encodeFields, decodeFields } from './protocol/fields.js';
export type { FieldDef } from './protocol/fields.js';
export { encodeTime, decodeTime } from './protocol/time.js';
export { CLIENT_PROTOCOL } from './protocol/constants.js';

export * from './proto/index_pb.js';
