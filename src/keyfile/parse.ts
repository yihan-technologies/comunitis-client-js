import { fromBinary } from '@bufbuild/protobuf';
import { BootDataSchema, KeyFileUpdateSchema, type BootData, type NetworkCredential } from '../proto/index_pb.js';

export interface ServerKeyFileData {
  privKey: Uint8Array;        // raw 64-byte Ed25519 private key [seed(32)||pub(32)]
  pubKey: Uint8Array;         // raw 32-byte Ed25519 public key
  network: NetworkCredential | undefined;
}

// Derive 32-byte AES key: SHA-256(UTF-8 password) — mirrors Go's deriveKey().
async function deriveKey(password: string): Promise<CryptoKey> {
  const pw = new TextEncoder().encode(password);
  const raw = await crypto.subtle.digest('SHA-256', pw);
  return crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['decrypt']);
}

// AES-256-GCM decrypt: format is [12-byte nonce][ciphertext+tag].
async function aesDecrypt(key: CryptoKey, data: Uint8Array): Promise<Uint8Array> {
  if (data.length < 12) throw new Error('encrypted blob too short');
  const iv = data.slice(0, 12);
  const ct = data.slice(12);
  const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
  return new Uint8Array(plain);
}

// Read one [4-byte LE length][blob] frame from buf at offset. Returns [plaintext, nextOffset].
async function readFrame(buf: Uint8Array, offset: number, key: CryptoKey): Promise<[Uint8Array, number]> {
  if (offset + 4 > buf.length) throw new Error('unexpected end of key file');
  const len = new DataView(buf.buffer, buf.byteOffset + offset, 4).getUint32(0, true);
  offset += 4;
  if (offset + len > buf.length) throw new Error('frame extends beyond file');
  const encrypted = buf.slice(offset, offset + len);
  const plain = await aesDecrypt(key, encrypted);
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
 * Format: sequence of [4-byte LE length][AES-256-GCM encrypted blob] frames.
 * - Frame 0: encrypted BootData protobuf (contains private key + network config).
 * - Frames 1+: encrypted KeyFileUpdate protobufs (optional append-only mutations).
 *
 * The encryption key is SHA-256(password).
 *
 * @throws if password is wrong (decryption fails) or file is corrupt.
 */
export async function parseServerKeyFile(data: Uint8Array, password: string): Promise<ServerKeyFileData> {
  const key = await deriveKey(password);

  // Read first frame — BootData
  const [frame0, next] = await readFrame(data, 0, key).catch(() => {
    throw new Error('Wrong password or corrupt key file');
  });
  const bootData = fromBinary(BootDataSchema, frame0);

  // Apply any KeyFileUpdate frames
  let offset = next;
  while (offset < data.length) {
    try {
      const [frame, nextOff] = await readFrame(data, offset, key);
      const update = fromBinary(KeyFileUpdateSchema, frame);
      applyUpdate(bootData, update);
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
    // Derive pubkey from seed (first 32 bytes of 64-byte privkey)
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
