import { createLibp2p } from 'libp2p';
import { webSockets } from '@libp2p/websockets';
import { fromString } from 'uint8arrays/from-string'
import { webRTC } from '@libp2p/webrtc';
import { webTransport } from '@libp2p/webtransport';
import { circuitRelayTransport } from '@libp2p/circuit-relay-v2';
import { noise } from '@chainsafe/libp2p-noise';
import { yamux } from '@chainsafe/libp2p-yamux';
import { bootstrap } from '@libp2p/bootstrap';
import { ComunitisKadDHT, CLIENT_PROTOCOL as DHT_PROTOCOL } from '../dht/index.js';
import { identify } from '@libp2p/identify';
import { dcutr } from '@libp2p/dcutr';
import { ping } from '@libp2p/ping';
import { preSharedKey } from '@libp2p/pnet';
import { multiaddr } from '@multiformats/multiaddr';
import { create as pbCreate, toBinary, fromBinary } from '@bufbuild/protobuf';
import type { Libp2p, PeerId, Stream, Connection } from '@libp2p/interface';
import type { ClientConfig, RequestOptions } from './types.js';
import { CLIENT_PROTOCOL } from '../protocol/constants.js';
import { sendAndReceive, writeMessage, readMessage } from '../protocol/stream.js';
import { signRequest, signResponse, verifyResponse } from '../protocol/signing.js';
import {
  TransferSingleSchema, type TransferSingle,
  type CreateComunitiInitialResponse, CreateComunitiInitialResponseSchema,
  CreateComunitiInitialSchema,
  type CreateComunitiFinal, CreateComunitiFinalSchema,
  type CreateComunitiResponse, CreateComunitiResponseSchema,
  type BatchEntryResponseList, BatchEntryResponseListSchema,
  type BatchEntry,
  BatchEntryRequestSchema,
  type GraphQueryResponse, GraphQueryResponseSchema,
  GraphQueryRequestSchema,
  SingleInst,
  type Response,
} from '../proto/index_pb.js';

export interface ServerStatsResponse {
  serverPeerCount: number;
  serverPeers: string[];
  clientPeerCount: number;
  clientPeers: string[];
  ramTotalBytes: number;
  ramUsedBytes: number;
  ramFreeBytes: number;
  cpuUsedPercent: number;
  diskTotalBytes: number;
  diskUsedBytes: number;
  diskFreeBytes: number;
  timestamp: number;
}

// ponytail: cast avoids proto regeneration; wire value is raw int32
const SERVER_STATS_INST = 19 as unknown as SingleInst;
import { randomUUID } from '../util/uuid.js';
import { peerIdFromString } from '@libp2p/peer-id';

// Encode a raw 32-byte Ed25519 public key as a libp2p pb.PublicKey protobuf:
//   field 1 (KeyType = Ed25519 = 1): 0x08 0x01
//   field 2 (Data, 32 bytes):        0x12 0x20 [32 bytes]
// This is what Go's crypto.UnmarshalPublicKey() expects.
function marshalEd25519PubKey(rawPub: Uint8Array): Uint8Array {
  const out = new Uint8Array(4 + rawPub.length);
  out[0] = 0x08; out[1] = 0x01;
  out[2] = 0x12; out[3] = rawPub.length;
  out.set(rawPub, 4);
  return out;
}

// Extract the raw 32-byte Ed25519 pubkey from a marshaled libp2p pb.PublicKey.
// Format: [0x08, 0x01, 0x12, <len>, ...key bytes]
function unmarshalEd25519PubKey(marshaled: Uint8Array): Uint8Array | null {
  if (marshaled.length < 36 || marshaled[0] !== 0x08 || marshaled[1] !== 0x01 ||
      marshaled[2] !== 0x12 || marshaled[3] !== 32) {
    return null;
  }
  return marshaled.slice(4, 36);
}

const MIN_PEERS = 3;
const RECONNECT_INTERVAL_MS = 10_000;

export class ComunitisClient extends EventTarget {
  private config: ClientConfig;
  private node: Libp2p | null = null;
  private dht: ComunitisKadDHT | null = null;
  private reconnectTimer: ReturnType<typeof setInterval> | null = null;
  // Peer IDs parsed from bootstrap addresses — these are the server peers.
  private bootstrapPeerIds: Set<string> = new Set();

  /**
   * Async alternative to addEventListener('request', ...) for inbound requests.
   * Receives the parsed request and a respond callback. Awaited before the
   * default empty response is sent, so async handlers work correctly.
   */
  public onRequest?: (req: TransferSingle, respond: (data: Uint8Array) => Promise<void>) => Promise<void>;

  constructor(config: ClientConfig) {
    super();
    this.config = config;
  }

  async connect(): Promise<void> {
    const cfg = this.config;
    //const usePSK = cfg.clientPSK != null && cfg.clientPSK.length > 0;

    this.node = await createLibp2p({
      transports: [
        webSockets(),
        webRTC(),
        webTransport(),
        circuitRelayTransport(),
      ],
      connectionEncrypters: [noise()],
      //...(usePSK ? { connectionProtector: preSharedKey({ psk: cfg.clientPSK! }) } : {}),
      streamMuxers: [yamux()],
      // ponytail: allow private IPs and plain ws — browser default blocks both; server handles auth
      connectionGater: {
        denyDialMultiaddr: () => false,
      },
      peerDiscovery: [
        bootstrap({ list: cfg.bootstrapAddresses }),
      ],
      services: {
        ping: ping(),
        identify: identify(),
        dcutr: dcutr(),
      },
    });

    // Register as a full peer: handle inbound requests from other clients
    await this.node.handle(CLIENT_PROTOCOL, (stream: Stream, connection: Connection) => {
      this.handleInbound(stream, connection).catch(() => stream.abort(new Error('handler error')));
    });

    // Track peer count changes and emit events for consumers.
    const onPeerChange = () => this.dispatchEvent(new CustomEvent('peercountchange'));
    this.node.addEventListener('peer:connect', onPeerChange);
    this.node.addEventListener('peer:disconnect', onPeerChange);

    let started = false;
    try {
      await this.node.start();
      started = true;

      if (cfg.bootstrapAddresses.length === 0) {
        throw new Error('no bootstrap addresses configured');
      }

      // In browsers only WebSocket, WebRTC, and WebTransport work — raw TCP is silently
      // skipped by all transports which causes auto-dial to fail without a clear error.
      // Prefer browser-compatible addresses; fall back to all if none are tagged.
      const compat = cfg.bootstrapAddresses.filter(
        a => /\/ws($|\/)/.test(a) || a.includes('/webrtc') || a.includes('/webtransport')
      );
      const toDialStrs = compat.length > 0 ? compat : cfg.bootstrapAddresses;
      const toDialMas = toDialStrs.map(a => multiaddr(a));

      console.log('[p2p] dialing bootstrap peers:', toDialStrs);

      // Dial all filtered addresses in parallel — succeed as soon as one connects.
      // This bypasses the bootstrap-module auto-dial race that can stall on raw TCP.
      await Promise.any(
        toDialMas.map(ma =>
          this.node!.dial(ma, { signal: AbortSignal.timeout(15000) }).catch(e => {
            console.warn('[p2p] dial failed:', ma.toString(), e?.message);
            throw e;
          })
        )
      ).catch(() => { throw new Error('could not connect to any bootstrap peer'); });

      console.log('[p2p] connected, peers:', this.node.getPeers().map(p => p.toString()));

      // Record bootstrap peer IDs for fast server discovery — extract /p2p/<id> from each addr.
      this.bootstrapPeerIds.clear();
      
      for (const addrStr of cfg.bootstrapAddresses) {
        const m = addrStr.match(/\/p2p\/([^/]+)/);
        if (m?.[1]) this.bootstrapPeerIds.add(m[1]);
      }

      // Start custom DHT and fill routing table from the connected peer.
      this.dht = new ComunitisKadDHT(this.node, DHT_PROTOCOL);
      await this.dht.start();
      await this.dht.refreshRoutingTable().catch((e) => {
        console.log("START DHT ERROR: ", e)
      });

      this.startReconnectLoop();
    } catch (err) {
      if (started) await Promise.resolve(this.node.stop()).catch(() => null);
      else this.node.removeEventListener('peer:connect', onPeerChange);
      this.node = null;
      throw err;
    }
  }

  async disconnect(): Promise<void> {
    if (this.reconnectTimer) {
      clearInterval(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    if (this.dht) {
      await this.dht.stop().catch(() => null);
      this.dht = null;
    }
    if (this.node) {
      await this.node.stop();
      this.node = null;
    }
  }

  private startReconnectLoop(): void {
    this.reconnectTimer = setInterval(async () => {
      const node = this.node;
      if (!node) return;

      const peers = node.getPeers();
      if (peers.length >= MIN_PEERS) return;

      console.log(`[p2p] peer count ${peers.length} < ${MIN_PEERS}, reconnecting...`);

      const connectedIds = new Set(peers.map(p => p.toString()));

      // 1. Try DHT routing table peers first (libp2p peerStore has their addrs).
      if (this.dht) {
        const dhtPeers = this.dht.getKnownPeerIds().filter(p => !connectedIds.has(p.toString()));
        if (dhtPeers.length > 0) {
          await Promise.allSettled(
            dhtPeers.map(p =>
              node.dial(p, { signal: AbortSignal.timeout(RECONNECT_INTERVAL_MS) }).catch(e => {
                console.warn('[p2p] dht reconnect failed:', p.toString(), e?.message);
              })
            )
          );
          if (node.getPeers().length >= MIN_PEERS) return;
        }
      }

      // 2. Fall back to bootstrap addresses.
      const cfg = this.config;
      const compat = cfg.bootstrapAddresses.filter(
        a => /\/ws($|\/)/.test(a) || a.includes('/webrtc') || a.includes('/webtransport')
      );
      const toDialStrs = compat.length > 0 ? compat : cfg.bootstrapAddresses;
      const toRedial = toDialStrs.filter(a => {
        const m = a.match(/\/p2p\/([^/]+)/);
        return !m?.[1] || !connectedIds.has(m[1]);
      });

      await Promise.allSettled(
        toRedial.map(a =>
          node.dial(multiaddr(a), { signal: AbortSignal.timeout(RECONNECT_INTERVAL_MS) }).catch(e => {
            console.warn('[p2p] bootstrap reconnect failed:', a, e?.message);
          })
        )
      );
    }, RECONNECT_INTERVAL_MS);
  }

  /** Find which servers host a given comuniti via DHT. */
  async findComunitiServers(comunitiId: string): Promise<Uint8Array | null> {
    return this.dht?.findComunitiServers(comunitiId) ?? null;
  }

  get peerId(): PeerId | undefined {
    return this.node?.peerId;
  }

  getPeerCount(): number {
    return this.node?.getPeers().length ?? 0;
  }

  // ── Protocol methods (outbound) ─────────────────────────────────────────────

  async createComunitiInitial(
    name: string,
    isPublic: boolean,
    opts?: RequestOptions,
  ): Promise<CreateComunitiInitialResponse> {
    const req = pbCreate(CreateComunitiInitialSchema, { Name: name, Public: isPublic });
    const data = toBinary(CreateComunitiInitialSchema, req);
    const raw = await this.request(SingleInst.CREATE_COMUNITI_INIT, data, opts);
    return fromBinary(CreateComunitiInitialResponseSchema, raw);
  }

  async createComunitiFinal(req: CreateComunitiFinal, opts?: RequestOptions): Promise<CreateComunitiResponse> {
    const data = toBinary(CreateComunitiFinalSchema, req);
    const raw = await this.request(SingleInst.CREATE_COMUNITI_FINAL, data, opts);
    return fromBinary(CreateComunitiResponseSchema, raw);
  }

  async batchEntry(
    entries: BatchEntry[],
    durableWrite = false,
    opts?: RequestOptions,
  ): Promise<BatchEntryResponseList> {
    const req = pbCreate(BatchEntryRequestSchema, { Entries: entries, DurableWrite: durableWrite });
    const data = toBinary(BatchEntryRequestSchema, req);
    const raw = await this.request(SingleInst.BATCH_ENTRY, data, opts);
    return fromBinary(BatchEntryResponseListSchema, raw);
  }

  async graphQuery(
    query: string,
    keyID: bigint,
    minIndex = 0,
    opts?: RequestOptions,
  ): Promise<GraphQueryResponse> {
    const req = pbCreate(GraphQueryRequestSchema, { Query: query, KeyID: keyID, MinIndex: minIndex });
    const data = toBinary(GraphQueryRequestSchema, req);
    const raw = await this.request(SingleInst.GRAPH_QUERY, data, opts);
    return fromBinary(GraphQueryResponseSchema, raw);
  }

  async expressionCall(data: Uint8Array, opts?: RequestOptions): Promise<Uint8Array> {
    return this.request(SingleInst.EXPRESSION_CALL, data, opts);
  }

  async serverStats(opts?: RequestOptions): Promise<ServerStatsResponse> {
    const raw = await this.request(SERVER_STATS_INST, new Uint8Array(), opts);
    const wrapper = fromBinary(GraphQueryResponseSchema, raw);
    const returned =  JSON.parse(new TextDecoder().decode(wrapper.Data)) as ServerStatsResponse;
    //console.log("SERVER STATS RETURNED: ", returned)
    return returned
  }

  // ── Internal request/response ───────────────────────────────────────────────

  private async request(inst: SingleInst, data: Uint8Array, opts?: RequestOptions): Promise<Uint8Array> {
    const node = this.node;
    if (!node) throw new Error('client not connected');

    const comunitiID = opts?.comunitiID ?? this.config.comunitiID ?? '';
    const timeout = opts?.timeout ?? this.config.requestTimeout ?? 30000;
    const requestId = randomUUID();

    const { time, signature } = signRequest(this.config.signingKeyPriv, requestId, data);
    const timeMs = new DataView(time.buffer, time.byteOffset, 8).getBigInt64(0, true);

    const transfer = pbCreate(TransferSingleSchema, {
      ComunitiID: comunitiID,
      Inst: inst,
      RequestID: requestId,
      Data: data,
      Signature: signature,
      Key: marshalEd25519PubKey(this.config.signingKeyPub),
      Time: timeMs,
      Return: true,
    });

    const wire = toBinary(TransferSingleSchema, transfer);

    // Find target peer
    let conn: Connection;
    if (opts?.targetPeer) {
      conn = await node.dial(opts.targetPeer, { signal: AbortSignal.timeout(timeout) });
    } else {
      const serverPeerId = await this.discoverServer(timeout);
      conn = await node.dial(serverPeerId, { signal: AbortSignal.timeout(timeout) });
    }

    const stream = await conn.newStream(CLIENT_PROTOCOL, { signal: AbortSignal.timeout(timeout) });
    const responseBytes = await sendAndReceive(stream, wire);

    const response = fromBinary(TransferSingleSchema, responseBytes);
    const res = response.Responses[0] as Response | undefined;
    if (!res) throw new Error('empty response');

    // Verify the response signature before acting on the payload.
    // If serverSigningKeyPub is configured, use it for strict verification.
    // Otherwise fall back to the self-asserted key in the response (ensures
    // integrity but not that the peer is the expected server).
    const verifyPub = this.config.serverSigningKeyPub ?? unmarshalEd25519PubKey(res.Key);
    if (verifyPub && res.Signature?.length) {
      const timeBuf = new Uint8Array(8);
      new DataView(timeBuf.buffer).setBigInt64(0, res.Time, true);
      if (!verifyResponse(verifyPub, requestId, timeBuf, res.Data, res.Signature)) {
        throw new Error('invalid response signature');
      }
    }

    if (res.ErrCode != null || res.Err) {
      throw Object.assign(new Error(res.Err ?? 'server error'), { code: res.ErrCode });
    }

    return res.Data;
  }

  // ── Inbound handler (client↔client) ────────────────────────────────────────

  private async handleInbound(stream: Stream, _connection: Connection): Promise<void> {
    const reqBytes = await readMessage(stream);
    const req = fromBinary(TransferSingleSchema, reqBytes);

    let respondCalled = false;

    const respond = async (data: Uint8Array) => {
      if (respondCalled) return;
      respondCalled = true;

      const signature = signResponse(this.config.signingKeyPriv, req.RequestID, req.Time, data);

      const response = pbCreate(TransferSingleSchema, {
        ComunitiID: req.ComunitiID,
        RequestID: req.RequestID,
        Responses: [{
          Time: req.Time,
          Data: data,
          Key: marshalEd25519PubKey(this.config.signingKeyPub),
          Signature: signature,
        }],
      });
      await writeMessage(stream, toBinary(TransferSingleSchema, response));
    };

    if (this.onRequest) {
      // Async handler path: await the handler so it can call respond() after
      // any number of awaits without racing the default response.
      await this.onRequest(req, respond);
    } else {
      // Legacy synchronous event path: dispatch and fall back to empty response
      // if the listener didn't call respond() synchronously.
      const event = Object.assign(new Event('request'), { req, respond });
      this.dispatchEvent(event);
    }

    if (!respondCalled) {
      await respond(new Uint8Array(0));
    }
  }

  // ── Peer discovery via DHT ──────────────────────────────────────────────────

  private async discoverServer(timeout: number): Promise<PeerId> {
    const node = this.node!;

    //Fast path: return a connected bootstrap peer (= server) directly.
    for (const peer of node.getPeers()) {
      if (this.bootstrapPeerIds.has(peer.toString())) {
        return peer;
      }
    }

    const rootPeerID =  peerIdFromString(this.config.comunitiID as string)

    const res = await this.dht?.findPeer(rootPeerID)
    if(res != undefined){
      return res?.id
    }

    // Slow path: re-dial bootstrap addresses.
    const cfg = this.config;
    const compat = cfg.bootstrapAddresses.filter(
      a => /\/ws($|\/)/.test(a) || a.includes('/webrtc') || a.includes('/webtransport')
    );
    const toDialStrs = compat.length > 0 ? compat : cfg.bootstrapAddresses;
    try {
      const conn = await Promise.any(
        toDialStrs.map(a =>
          node.dial(multiaddr(a), { signal: AbortSignal.timeout(timeout) }).catch(e => { throw e; })
        )
      );
      return conn.remotePeer;
    } catch {
      // intentional fall-through
    }

    throw new Error('no server peer found for discovery key: ' + this.config.clientDiscoveryKey);
  }


  //   private async discoverServer(timeout: number): Promise<PeerId> {
  //   const node = this.node!;

  //   // Server peer IDs come from bootstrap addresses — check connected peers first.
  //   for (const peer of node.getPeers()) {
  //     if (this.bootstrapPeerIds.has(peer.toString())) {
  //       return peer;
  //     }
  //   }

  //   // Not currently connected — re-dial bootstrap addresses.
  //   const cfg = this.config;
  //   const compat = cfg.bootstrapAddresses.filter(
  //     a => /\/ws($|\/)/.test(a) || a.includes('/webrtc') || a.includes('/webtransport')
  //   );
  //   const toDialStrs = compat.length > 0 ? compat : cfg.bootstrapAddresses;
  //   const conn = await Promise.any(
  //     toDialStrs.map(a =>
  //       node.dial(multiaddr(a), { signal: AbortSignal.timeout(timeout) }).catch(e => {
  //         console.warn('[p2p] reconnect failed:', a, e?.message);
  //         throw e;
  //       })
  //     )
  //   ).catch(() => { throw new Error('could not reconnect to any server'); });

  //   return conn.remotePeer;
  // }


}
