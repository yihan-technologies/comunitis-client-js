import { fromBinary } from '@bufbuild/protobuf';
import { argon2id } from 'hash-wasm';
import { BootDataSchema, KeyFileUpdateSchema, type BootData, type NetworkCredential } from '../proto/index_pb.js';

export interface ServerKeyFileData {
  privKey: Uint8Array;        // raw 64-byte Ed25519 private key [seed(32)||pub(32)]
  pubKey: Uint8Array;         // raw 32-byte Ed25519 public key
  network: NetworkCredential | undefined;
}

// Magic: "CMKF" + version 1 — new Argon2id format sentinel.
const KEYFILE_MAGIC = new Uint8Array([0x43, 0x4d, 0x4b, 0x46, 0x01, 0x00, 0x00, 0x00]);
const KEYFILE_SALT_LEN = 32;

function magicMatches(data: Uint8Array): boolean {
  if (data.length < KEYFILE_MAGIC.length) return false;
  for (let i = 0; i < KEYFILE_MAGIC.length; i++) {
    if (data[i] !== KEYFILE_MAGIC[i]) return false;
  }
  return true;
}

// SHA-256(UTF-8 password) → 32 bytes. Mirrors Go deriveKey().
async function sha256Password(password: string): Promise<Uint8Array> {
  const raw = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(password));
  return new Uint8Array(raw);
}

// Argon2id(intermediate, salt) → 32-byte AES key. Mirrors Go deriveKeyArgon2id().
async function argon2idDeriveKey(intermediate: Uint8Array, salt: Uint8Array): Promise<Uint8Array> {
  const hex = await argon2id({
    password: intermediate,
    salt,
    iterations: 3,
    memorySize: 65536,
    parallelism: 4,
    hashLength: 32,
    outputType: 'hex',
  });
  const result = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) result[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  return result;
}

// AES-256-GCM decrypt: format is [12-byte nonce][ciphertext+tag].
async function aesDecrypt(key: CryptoKey, data: Uint8Array): Promise<Uint8Array> {
  if (data.length < 12) throw new Error('encrypted blob too short');
  const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: data.slice(0, 12) }, key, data.slice(12));
  return new Uint8Array(plain);
}

// Read one [4-byte LE length][blob] frame from buf at offset. Returns [plaintext, nextOffset].
async function readFrame(buf: Uint8Array, offset: number, key: CryptoKey): Promise<[Uint8Array, number]> {
  if (offset + 4 > buf.length) throw new Error('unexpected end of key file');
  const len = new DataView(buf.buffer, buf.byteOffset + offset, 4).getUint32(0, true);
  offset += 4;
  if (offset + len > buf.length) throw new Error('frame extends beyond file');
  const plain = await aesDecrypt(key, buf.slice(offset, offset + len));
  return [plain, offset + len];
}

// Extract raw 32-byte Ed25519 pubkey from libp2p-marshaled format: [0x08,0x01,0x12,0x20,...32b].
function unmarshalPubKey(marshaled: Uint8Array): Uint8Array | null {
  if (marshaled.length >= 36 && marshaled[0] === 0x08 && marshaled[1] === 0x01 &&
      marshaled[2] === 0x12 && marshaled[3] === 32) {
    return marshaled.slice(4, 36);
  }
  return null;
}

// Apply a KeyFileUpdate to BootData in place (mirrors Go applyKeyFileUpdate).
function applyUpdate(data: BootData, u: ReturnType<typeof fromBinary<typeof KeyFileUpdateSchema>>): void {
  if (u.SetNetwork) data.Network = u.SetNetwork;
  if (u.UpdatePubKey && u.UpdatePubKey.length > 0) data.PubKey = u.UpdatePubKey;
  if (u.UpdatePrivKey && u.UpdatePrivKey.length > 0) data.PrivKey = u.UpdatePrivKey;

  const net = data.Network;
  if (!net) return;

  if (u.AddAddresses.length > 0) net.Addresses.push(...u.AddAddresses);
  if (u.RemoveAddresses.length > 0) {
    const remove = new Set(u.RemoveAddresses);
    net.Addresses = net.Addresses.filter(a => !remove.has(a));
  }
  if (u.SetNetworkID) net.NetworkID = u.SetNetworkID;
  if (u.SetRootComunitiID) net.RootComunitiID = u.SetRootComunitiID;
  if (u.SetNetworkName) net.Name = u.SetNetworkName;
  if (u.SetDiscoveryKey) net.DiscoveryKey = u.SetDiscoveryKey;
  if (u.SetPSK && u.SetPSK.length > 0) net.PSK = u.SetPSK;
  if (u.SetClientPSK && u.SetClientPSK.length > 0) net.ClientPSK = u.SetClientPSK;
  if (u.SetClientDiscoveryKey) net.ClientDiscoveryKey = u.SetClientDiscoveryKey;
  if (u.DeleteNetwork) net.Deleted = true;
}

/**
 * Parse a binary key file produced by the Comunitis Go server.
 *
 * New format (magic "CMKF\x01\x00\x00\x00" at byte 0):
 *   [8-byte magic][32-byte Argon2id salt][frames...]
 *   AES key = Argon2id(SHA-256(password), salt, t=3, m=65536, p=4, keyLen=32)
 *
 * Legacy format (no magic):
 *   [frames...]
 *   AES key = SHA-256(password)
 *
 * Each frame: [4-byte LE uint32 length][AES-256-GCM ciphertext]
 * Frame 0 → BootData proto; Frame 1+ → KeyFileUpdate proto (applied in order).
 *
 * @throws if password is wrong (decryption fails) or file is corrupt.
 */
export async function parseServerKeyFile(data: Uint8Array, password: string): Promise<ServerKeyFileData> {
  const intermediate = await sha256Password(password);

  let frameOffset: number;
  let aesKeyRaw: Uint8Array;

  if (magicMatches(data)) {
    // New format: Argon2id KDF with per-file salt.
    if (data.length < 8 + KEYFILE_SALT_LEN) throw new Error('Key file too short');
    const salt = data.slice(8, 8 + KEYFILE_SALT_LEN);
    aesKeyRaw = await argon2idDeriveKey(intermediate, salt);
    frameOffset = 8 + KEYFILE_SALT_LEN;
  } else {
    // Legacy format: SHA-256 only.
    aesKeyRaw = intermediate;
    frameOffset = 0;
  }

  const aesKey = await crypto.subtle.importKey('raw', aesKeyRaw, 'AES-GCM', false, ['decrypt']);

  // Read first frame — BootData
  const [frame0, next] = await readFrame(data, frameOffset, aesKey).catch(() => {
    throw new Error('Wrong password or corrupt key file');
  });
  const bootData = fromBinary(BootDataSchema, frame0);

  // Apply any KeyFileUpdate frames
  let offset = next;
  while (offset < data.length) {
    try {
      const [frame, nextOff] = await readFrame(data, offset, aesKey);
      applyUpdate(bootData, fromBinary(KeyFileUpdateSchema, frame));
      offset = nextOff;
    } catch {
      break; // EOF or partial trailing data — stop
    }
  }

  const rawPriv = bootData.PrivKey;
  if (!rawPriv || rawPriv.length < 32) throw new Error('Key file missing private key');

  let rawPub: Uint8Array;
  if (bootData.PubKey && bootData.PubKey.length > 0) {
    rawPub = unmarshalPubKey(bootData.PubKey) ?? bootData.PubKey.slice(0, 32);
  } else {
    const { ed25519 } = await import('@noble/curves/ed25519.js');
    rawPub = ed25519.getPublicKey(rawPriv.slice(0, 32));
  }

  // Ensure privKey is 64 bytes [seed||pub]
  let privKey = rawPriv;
  if (privKey.length === 32) {
    const combined = new Uint8Array(64);
    combined.set(privKey, 0);
    combined.set(rawPub, 32);
    privKey = combined;
  }

  return { privKey, pubKey: rawPub, network: bootData.Network };
}
