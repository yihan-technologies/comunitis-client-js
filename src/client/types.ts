import type { PeerId } from '@libp2p/interface';

export interface ClientConfig {
  bootstrapAddresses: string[];
  clientPSK?: Uint8Array;         // 32-byte PSK from NetworkCredential.ClientPSK; omit for no-PSK connections
  clientDiscoveryKey: string;     // NetworkCredential.ClientDiscoveryKey
  signingKeyPriv: Uint8Array;     // 64-byte Ed25519 private key [seed(32)||pub(32)]
  signingKeyPub: Uint8Array;      // 32-byte Ed25519 public key
  accountKeyPriv?: Uint8Array;    // 64-byte Ed25519 private key [seed(32)||pub(32)]; required for account self-service requests
  accountKeyPub?: Uint8Array;     // 32-byte Ed25519 public key of the account key
  serverSigningKeyPub?: Uint8Array; // 32-byte Ed25519 public key of the server; enables strict response verification
  comunitiID?: string;            // default comunitiID for requests
  requestTimeout?: number;        // ms, default 30000
}

export interface RequestOptions {
  targetPeer?: PeerId;
  comunitiID?: string;
  timeout?: number;
}
