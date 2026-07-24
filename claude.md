# TypeScript SDK — `comunitis-client-js/`

**Package:** `comunitis-client` v0.0.1 | **Module:** ESM+CJS dual | **Platform:** browser

## All Public Exports (`src/index.ts`)
```ts
// Client
ComunitisClient, ClientConfig, RequestOptions, ServerStatsResponse
RootObjectBlocksResponse                           // from proto

// Proto (all re-exported)
export * from './proto/index_pb.js'                // all messages, schemas, enums

// Key management
KeyManager, KeyManagerOptions
KeyMeta, FieldKeyChain, FieldKeyVersion, AltSalt, ExportBundle
KeyTypeSigning, KeyTypeEncryption, KeyStatusActive, KeyStatusRevoked
ChainStatusActive, ChainStatusRevoked

// Storage
IStorage, StorageOptions

// Key file parsers
parseServerKeyFile, ServerKeyFileData
parseGoExportBundle, GoExportBundleData

// Protocol utilities
encodeFields, decodeFields, FieldDef
encodeTime, decodeTime
CLIENT_PROTOCOL                                    // '/comunitisdb-client/1.0.0'
decodeRootBlock, parseRootConfig
ComunitiStructure, ObjectDef, LinkDef, LinkServerDef, ServerDef
RoleDef, FieldSpec, ValidationSpec, LinkFieldSpec, TrustedServer
```

## `ComunitisClient` API (`src/client/index.ts`)
```ts
constructor(config: ClientConfig)
connect(): Promise<void>
disconnect(): Promise<void>
findComunitiServers(comunitiId: string): Promise<Uint8Array | null>
createComunitiInitial(req: CreateComunitiInitial, opts?): Promise<CreateComunitiInitialResponse>
createComunitiFinal(req: CreateComunitiFinal, opts?): Promise<CreateComunitiResponse>
batchEntry(entries: BatchEntry[], opts?): Promise<BatchEntryResponseList>
graphQuery(query: string, keyID: bigint, minIndex?: number, opts?): Promise<GraphQueryResponse>
expressionCall(data: Uint8Array, opts?): Promise<Uint8Array>
serverStats(opts?): Promise<ServerStatsResponse>
rootObjectBlocks(fileIDIndex?: number, fileInternalIndex?: number, opts?): Promise<RootObjectBlocksResponse>
onRequest?: (req: TransferSingle, respond: (data: Uint8Array) => Promise<void>) => Promise<void>
```

**`ClientConfig`:**
```ts
{
  bootstrapAddresses: string[]       // multiaddrs
  clientPSK?: Uint8Array             // 32 bytes
  clientDiscoveryKey: string
  signingKeyPriv: Uint8Array         // 64-byte Ed25519 [seed(32)||pub(32)]
  signingKeyPub: Uint8Array          // 32-byte Ed25519 pubkey
  serverSigningKeyPub?: Uint8Array
  comunitiID?: string                // default comuniti for requests
  requestTimeout?: number            // default 30000ms
}
```

**`RequestOptions`:**
```ts
{ comunitiID?: string; targetPeer?: PeerId; timeout?: number }
```

**`ServerStatsResponse`:**
```ts
{
  serverPeerCount: number; serverPeers: string[]
  clientPeerCount: number; clientPeers: string[]
  ramTotalBytes: bigint; ramUsedBytes: bigint; ramFreeBytes: bigint
  cpuUsedPercent: number
  diskTotalBytes: bigint; diskUsedBytes: bigint; diskFreeBytes: bigint
  timestamp: bigint
}
```

## Wire Protocol (`src/protocol/stream.ts`)
- Protocol ID: `/comunitisdb-client/1.0.0`
- Format: raw protobuf bytes (`TransferSingle`), no length prefix
- Flow: write bytes → `stream.close()` (close write side) → read all response bytes
- Go server: `io.ReadAll(stream)` then writes response
- Concurrency: JS starts read promise before closing write to avoid deadlock

## Server Discovery Strategy
1. Connected peers already in libp2p peerstore → dial directly
2. DHT lookup `findPeer(comunitiID as peerID)`
3. Re-dial bootstrap multiaddresses
4. Reconnect loop: every 10s, if peer count < 3 (MIN_PEERS), retry DHT + bootstrap

## DHT (`src/dht/`)
- Class: `ComunitisKadDHT`
- Protocols: `/comunitis/kad/server/1.0.0` (`DHT_SERVER_PROTOCOL`), `/comunitis/kad/client/1.0.0` (`DHT_CLIENT_PROTOCOL`)
- Parameters: K=20 (bucket size), ALPHA=3 (parallel lookups)
- Key namespaces: `/cn/<comunitiID>`, `/cc/<pubKey>`, `/peer/<peerID>`, `/prov/<key>`
- Operations: ping, FIND_NODE/NODES, STORE/STORE_ACK, FIND_VALUE/VALUE/VALUE_NODES

## `KeyManager` (`src/keymanager/`)
Two-level password encryption:
- **L1 password** → encrypts key metadata (labels, public keys, index)
- **L2 password** → encrypts private keys

Argon2id params: `time=3, memory=64MB (65536 KiB), parallelism=4, keyLen=32`

Key types:
- **Signing (Ed25519):** stored as `[seed(32)||pub(32)]` = 64 bytes
- **Encryption (X25519):** ECDH with SHA-512 KDF + AES-256-GCM
- **Field keys:** AES-256-GCM with time-based rotation (chains + versions)
- **Alt salts:** optional third encryption tier

Storage key namespace (using `IStorage`):
```
km:header         → plaintext JSON: { l1Salt, l2Salt }
km:index          → L1-encrypted: list of key IDs, chain IDs, alt salt IDs
km:meta:<id>      → L1-encrypted: KeyMeta (label, pubkey, type, status)
km:priv:<id>      → L2-encrypted: private key bytes
km:chain:<id>     → L1-encrypted: FieldKeyChain
km:versions:<id>  → L1-encrypted: FieldKeyVersion[]
km:fieldpriv:<vId>→ L2-encrypted: field key bytes
km:labels         → L1-encrypted: label↔keyID map
km:alt:<id>       → L2-encrypted: AltSalt record
km:altpriv:<id>:<altId> → alt-encrypted private key
```

Crypto stack: `@noble/curves/ed25519` (Ed25519 + x25519), `@noble/hashes/sha2`, Web Crypto API AES-256-GCM, `hash-wasm` Argon2id.

## `parseServerKeyFile` (`src/keyfile/parse.ts`)
Parses Go server binary key file:
```
Frame format: [4-byte LE uint32 len][AES-256-GCM ciphertext]
AES key = SHA-256(password)
Frame 0 → decrypt → BootData proto
Frame 1+ → decrypt → KeyFileUpdate proto (mutations applied in order)
```

## `parseGoExportBundle` (`src/keyfile/go-bundle.ts`)
Parses Go KMGR binary keystore:
```
Magic: 4B "KMGR" + 4B version [0x01,0x00,0x00,0x00]
Entries: [4-byte LE len][type(1)][payload]
  type 0: plaintext JSON header { l1Salt, l2Salt } (Argon2id salts, base64)
  type 1: L1-encrypted KeyMeta
  type 2: L2-encrypted private key bytes
```
Password derivation: `SHA-256(rawPassword)` → `Argon2id(time=3, mem=65536, par=4, keyLen=32)` → AES-256-GCM key.

## `decodeRootBlock` (`src/protocol/root-blocks.ts`)
Full decode pipeline:
```ts
// 1. Strip 37-byte StartTypeObject prefix if present
if (data.length > 37 && data[28] === 1 /*StartTypeObject*/) {
  data = data.slice(37);
}
// 2. Detect block type from RawType byte at position length-9
const rawType = data[data.length - 9];  // 7=Type8, 8=Type16, 9=Type32, 10=Type64
const lenBytes = RAW_TYPE_LEN[rawType]; // 1/2/4/8
// 3. Extract content (EncodeEntryBasic bytes)
const content = data.slice(16, data.length - 1 - lenBytes - 8);
// 4. Detect content type and strip header
const contentType = content[0];         // 11=Type8, 12=Type16, 13=Type32
const lenBytes2 = CONTENT_TYPE_LEN[contentType]; // 1/2/4
const dataStart = 1 + lenBytes2 + 88;  // 88 = Sig(64)+SignKeyID(8)+ProcID(8)+Time(8)
// 5. Decode as UTF-8 string
return new TextDecoder().decode(content.slice(dataStart));
```

## `parseRootConfig` (`src/protocol/root-blocks.ts`)
Parses root config string → `ComunitiStructure`:
```ts
interface ComunitiStructure {
  id: string; type: 'public'|'private'; name: string
  saltPublic: string; saltPrivate: string
  trustedServers: TrustedServer[]
  objects: ObjectDef[]
  links: LinkDef[]
  roles: RoleDef[]
}
```
Parsing: split on `\n` → trim → skip empty → `indexOf(': ')` → value.split(`' | '`).

## `encodeFields` / `decodeFields` (`src/protocol/fields.ts`)
```ts
interface FieldDef { fieldID: number; updateType: number; encLevel: number; value: Uint8Array }
// Wire: [FieldLen(2LE)][FieldID(1)][UpdateType(1)][EncLevel(1)][Value(N)]
// FieldLen = 5 + value.length
```

## Build
```bash
npm run proto   # buf generate → src/proto/index_pb.ts (reads ../comunitis/shared/protoint)
npm run build   # npm run proto + tsup → dist/index.{js,cjs,d.ts}
```
tsup config: `format: ['cjs','esm']`, `dts: true`, `platform: 'browser'`, bundles `netmask` inline.

## Known Quirks
- `SERVER_STATS` (19) and `ROOT_OBJECT_WRITE` (21) are in the generated enum; use `SingleInst.SERVER_STATS` directly (the `as unknown as SingleInst` casts were removed).
- Request signature payload: `RequestID || Time(8 LE) || Inst(4 LE) || ComunitiID || Data` — see `requestSignBytes` in `src/protocol/signing.ts`. Must match Go `requestSignPayload`.
- Proto source of truth: `../comunitis/shared/protoint/index.proto` — `buf.yaml` points there.
