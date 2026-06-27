import { createLibp2p } from 'libp2p';
import { webSockets } from '@libp2p/websockets';
import { webRTC } from '@libp2p/webrtc';
import { webTransport } from '@libp2p/webtransport';
import { circuitRelayTransport } from '@libp2p/circuit-relay-v2';
import { noise } from '@chainsafe/libp2p-noise';
import { yamux } from '@chainsafe/libp2p-yamux';
import { bootstrap } from '@libp2p/bootstrap';
import { kadDHT } from '@libp2p/kad-dht';
import { identify } from '@libp2p/identify';
import { dcutr } from '@libp2p/dcutr';
import { ping } from '@libp2p/ping';
import { preSharedKey } from '@libp2p/pnet';
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

// Module-level lazy multiformats imports — evaluated once on first call, not on
// every discoverServer invocation.
const _cidImport = import('multiformats/cid');
const _sha2Import = import('multiformats/hashes/sha2');

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

export class ComunitisClient extends EventTarget {
  private config: ClientConfig;
  private node: Libp2p | null = null;

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
      peerDiscovery: [
        bootstrap({ list: cfg.bootstrapAddresses }),
      ],
      services: {
        ping: ping(),
        // clientMode: true — participate in routing queries but don't store
        // records or serve as a full DHT node, reducing resource usage.
        dht: kadDHT({ clientMode: true }),
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

      console.log("NODE STARTED WITH ADDRESSES: ", this.config.bootstrapAddresses);

      // Wait for at least one bootstrap peer to connect (15s timeout).
      await new Promise<void>((resolve, reject) => {
        const peers = this.node!.getPeers();
        if (peers.length > 0) { resolve(); return; }
        const tid = setTimeout(() => reject(new Error('no bootstrap peer connected')), 15000);
        const handler = () => { clearTimeout(tid); resolve(); };
        this.node!.addEventListener('peer:connect', handler, { once: true });
      });

      console.log("CONNECTED TO: ", this.node.getPeers());

      // Refresh DHT routing table from the connected peer.
      const dhtSvc = (this.node.services as Record<string, unknown>)['dht'] as { refreshRoutingTable?: () => void | Promise<void> } | undefined;
      if (typeof dhtSvc?.refreshRoutingTable === 'function') {
        Promise.resolve(dhtSvc.refreshRoutingTable()).catch(() => null); // fire-and-forget
      }
    } catch (err) {
      // Clean up the node so the client can be reconnected.
      if (started) await Promise.resolve(this.node.stop()).catch(() => null);
      else this.node.removeEventListener('peer:connect', onPeerChange);
      this.node = null;
      throw err;
    }
  }

  async disconnect(): Promise<void> {
    if (this.node) {
      await this.node.stop();
      this.node = null;
    }
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
    return JSON.parse(new TextDecoder().decode(wrapper.Data)) as ServerStatsResponse;
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
    const signal = AbortSignal.timeout(timeout);

    const dht = (node.services as Record<string, unknown>)['dht'];
    if (!dht || typeof dht !== 'object') {
      throw new Error('DHT service not available');
    }

    // Build a CIDv1 (raw codec, sha256 multihash) matching go-libp2p's discutil.Advertise:
    //   nsToCid(ns) = cid.NewCidV1(cid.Raw, mh.Sum([]byte(ns), mh.SHA2_256, -1))
    const [{ CID }, { sha256 }] = await Promise.all([_cidImport, _sha2Import]);
    const keyBytes = new TextEncoder().encode(this.config.clientDiscoveryKey);
    const digest = await sha256.digest(keyBytes);
    const cid = CID.createV1(0x55 /* raw */, digest);
    
    console.log("LOOKING FOR PEERS: ")

    const findProviders = (dht as { findProviders?: Function })['findProviders'];
    if (typeof findProviders === 'function') {
      const gen = findProviders.call(dht, cid, { signal });
      for await (const provider of gen as AsyncIterable<{ id: PeerId }>) {
        if (provider.id.toString() !== node.peerId.toString()) {
          console.log("FOUND: PAIR IN DHT: ", provider.id)
          return provider.id;

        }
      }
    }

    throw new Error('no server peer found for discovery key: ' + this.config.clientDiscoveryKey);
  }
}
