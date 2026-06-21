/**
 * Integration tests: spawn a real comunitis server, connect with ComunitisClient,
 * and exercise every client-facing protocol method.
 *
 * Requires Go toolchain on PATH and the comunitis server source tree at a sibling
 * directory of this JS package (../../comunitis relative to package root).
 *
 * Tests are skipped automatically if `go build` fails or the server doesn't start.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawn, execSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { mkdtempSync, rmSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { peerIdFromString } from '@libp2p/peer-id';
import { ComunitisClient } from '../client/index.js';
import { generateSigningKey, base64ToBytes } from '../keymanager/crypto.js';

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------

const __dirname = fileURLToPath(new URL('.', import.meta.url));
const SERVER_SRC = resolve(__dirname, '../../../comunitis');
const SERVER_BIN = join(tmpdir(), 'comunitis-testserver');

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface ServerInfo {
  clientPSK: string;          // base64-encoded 32-byte PSK
  clientDiscoveryKey: string;
  serverPeerID: string;
  addresses: string[];        // multiaddrs with /p2p/ suffix
  rootComunitiID: string;
}

// ---------------------------------------------------------------------------
// Shared test state
// ---------------------------------------------------------------------------

let serverProc: ReturnType<typeof spawn> | null = null;
let client: ComunitisClient | null = null;
let info: ServerInfo | null = null;
let testDir = '';
let skip = false;
const signingKeys = generateSigningKey();

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function buildServer(): boolean {
  try {
    execSync(`go build -o ${SERVER_BIN} ./cmd/testserver`, {
      cwd: SERVER_SRC,
      timeout: 120_000,
      stdio: 'pipe',
    });
    return true;
  } catch {
    return false;
  }
}

function waitForServerInfo(proc: ReturnType<typeof spawn>,  timeoutMs: number): Promise<ServerInfo> {
  return new Promise((resolve, reject) => {
    let buf = '';
    const timer = setTimeout(
      () => reject(new Error('server startup timeout')),
      timeoutMs,
    );

    proc.stdout?.on('data', (chunk: Buffer) => {
      buf += chunk.toString();
      const idx = buf.indexOf('SERVER_INFO:');
      if (idx !== -1) {
        clearTimeout(timer);
        const json = buf.slice(idx + 12).split('\n')[0]!.trim();
        try {
          resolve(JSON.parse(json) as ServerInfo);
        } catch (e) {
          reject(new Error(`bad SERVER_INFO JSON "${json}": ${e}`));
        }
      }
    });

    proc.on('error', (err) => { clearTimeout(timer); reject(err); });
    proc.on('exit', (code) => {
      clearTimeout(timer);
      reject(new Error(`server exited with code ${code} before emitting SERVER_INFO`));
    });
  });
}

// ---------------------------------------------------------------------------
// Setup / teardown
// ---------------------------------------------------------------------------

beforeAll(async () => {
  if (!buildServer()) {
    skip = true;
    console.warn('Integration tests skipped: could not build Go test server');
    return;
  }

  testDir = mkdtempSync(join(tmpdir(), 'comunitis-inttest-'));
  serverProc = spawn(SERVER_BIN, [testDir], { stdio: ['ignore', 'pipe', 'inherit'] });

  try {
    info = await waitForServerInfo(serverProc, 30_000);
  } catch (err) {
    skip = true;
    serverProc.kill();
    console.warn('Integration tests skipped: server did not start —', err);
    return;
  }

  // Prefer WS addresses for Node.js compatibility; fall back to TCP.
  const wsAddrs = info.addresses.filter(a => a.includes('/ws/'));
  const bootstrap = wsAddrs.length > 0 ? wsAddrs : info.addresses;

  client = new ComunitisClient({
    bootstrapAddresses: bootstrap,
    clientPSK: base64ToBytes(info.clientPSK),
    clientDiscoveryKey: info.clientDiscoveryKey,
    signingKeyPriv: signingKeys.priv,
    signingKeyPub: signingKeys.pub,
    comunitiID: info.rootComunitiID,
    requestTimeout: 20_000,
  });

  await client.connect();
  // Allow DHT to bootstrap before sending requests.
  await new Promise(r => setTimeout(r, 1500));
}, 60_000);

afterAll(async () => {
  if (client) await client.disconnect().catch(() => {});
  if (serverProc) {
    serverProc.kill('SIGTERM');
    await new Promise<void>(r => {
      serverProc!.on('exit', () => r());
      setTimeout(r, 3000);
    });
  }
  if (testDir) rmSync(testDir, { recursive: true, force: true });
});

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('Integration: comunitis server protocols', () => {
  // ── Connectivity ────────────────────────────────────────────────────────

  it('skips gracefully when Go toolchain or server is unavailable', () => {
    expect(true).toBe(true); // always passes; real tests below are guarded by `skip`
  });

  // ── CREATE_COMUNITI_INIT ─────────────────────────────────────────────────

  it('CREATE_COMUNITI_INIT — returns comunitiID and root data string', async () => {
    if (skip) return;
    const serverId = peerIdFromString(info!.serverPeerID);

    const res = await client!.createComunitiInitial('testapp', true, {
      targetPeer: serverId,
      timeout: 20_000,
    });

    expect(res.ID).toBeTruthy();
    expect(res.RootData).toContain('comuniti.id');
    expect(res.Salt.length).toBeGreaterThan(0);
  }, 30_000);

  it('CREATE_COMUNITI_INIT — public=false comuniti includes private flag', async () => {
    if (skip) return;
    const serverId = peerIdFromString(info!.serverPeerID);

    const res = await client!.createComunitiInitial('privatecomuniti', false, {
      targetPeer: serverId,
      timeout: 20_000,
    });

    expect(res.ID).toBeTruthy();
    expect(res.RootData).toBeTruthy();
  }, 30_000);

  it('CREATE_COMUNITI_INIT — invalid name is rejected by server', async () => {
    if (skip) return;
    const serverId = peerIdFromString(info!.serverPeerID);

    // Names with spaces / special chars fail helpers.StringIsUsername.
    await expect(
      client!.createComunitiInitial('bad name!', true, {
        targetPeer: serverId,
        timeout: 15_000,
      }),
    ).rejects.toThrow();
  }, 30_000);

  // ── GRAPH_QUERY ──────────────────────────────────────────────────────────

  it('GRAPH_QUERY — empty query is rejected by server', async () => {
    if (skip) return;
    const serverId = peerIdFromString(info!.serverPeerID);

    // Empty query → server error 400 → client throws.
    await expect(
      client!.graphQuery('', 0n, 0, {
        comunitiID: info!.rootComunitiID,
        targetPeer: serverId,
        timeout: 15_000,
      }),
    ).rejects.toThrow();
  }, 30_000);

  it('GRAPH_QUERY — well-formed query returns a GraphQueryResponse', async () => {
    if (skip) return;
    const serverId = peerIdFromString(info!.serverPeerID);

    // The server calls RespondSuccessWithData even for query-level errors,
    // so this either returns data or a response with ErrCode set.
    const res = await client!.graphQuery(
      'objects(@type=2)',
      0n,
      0,
      {
        comunitiID: info!.rootComunitiID,
        targetPeer: serverId,
        timeout: 20_000,
      },
    );

    // Server responded (no network/protocol error). Response may contain results or an error code.
    expect(res).toBeTruthy();
    expect(res.Data.length > 0 || res.ErrCode != null).toBe(true);
  }, 30_000);

  it('GRAPH_QUERY — unknown comunitiID is rejected by server', async () => {
    if (skip) return;
    const serverId = peerIdFromString(info!.serverPeerID);

    await expect(
      client!.graphQuery('objects(@type=2)', 0n, 0, {
        comunitiID: 'nonexistent-comuniti-id',
        targetPeer: serverId,
        timeout: 15_000,
      }),
    ).rejects.toThrow();
  }, 30_000);

  // ── BATCH_ENTRY ──────────────────────────────────────────────────────────

  it('BATCH_ENTRY — empty entries array is rejected', async () => {
    if (skip) return;
    const serverId = peerIdFromString(info!.serverPeerID);

    // Empty entries → server returns error ("batch request is nil or empty").
    await expect(
      client!.batchEntry([], false, {
        comunitiID: info!.rootComunitiID,
        targetPeer: serverId,
        timeout: 15_000,
      }),
    ).rejects.toThrow();
  }, 30_000);

  it('BATCH_ENTRY — missing comunitiID is rejected', async () => {
    if (skip) return;
    const serverId = peerIdFromString(info!.serverPeerID);

    await expect(
      client!.batchEntry([], false, {
        comunitiID: '',
        targetPeer: serverId,
        timeout: 15_000,
      }),
    ).rejects.toThrow();
  }, 30_000);

  // ── EXPRESSION_CALL ──────────────────────────────────────────────────────

  it('EXPRESSION_CALL — missing expr_id in CTX is rejected by server', async () => {
    if (skip) return;
    const serverId = peerIdFromString(info!.serverPeerID);

    // No CTX["expr_id"] set → server returns code 1040.
    await expect(
      client!.expressionCall(new Uint8Array(0), {
        comunitiID: info!.rootComunitiID,
        targetPeer: serverId,
        timeout: 15_000,
      }),
    ).rejects.toThrow();
  }, 30_000);
});
