import type { Stream } from '@libp2p/interface';
import type { Uint8ArrayList } from 'uint8arraylist';

// libp2p v3+ MessageStream API:
//   stream.send(data)      — write bytes; returns false when the internal write
//                            buffer is full (backpressure). Data is still
//                            buffered internally — it is NOT dropped. A 'drain'
//                            event fires when it is safe to send again.
//   stream.close()         — half-close write side (signals EOF to remote)
//
// Go server uses io.ReadAll (reads until EOF) + raw stream.Write for responses.
// So we send raw proto bytes, close write, then read the raw response.

function toUint8Array(chunk: Uint8Array | Uint8ArrayList): Uint8Array {
  return chunk instanceof Uint8Array ? chunk : chunk.subarray();
}

async function readAll(stream: Stream): Promise<Uint8Array> {
  const chunks: Uint8Array[] = [];
  for await (const chunk of stream) {
    chunks.push(toUint8Array(chunk as Uint8Array<ArrayBufferLike> | Uint8ArrayList));
  }
  const total = chunks.reduce((sum, c) => sum + c.length, 0);
  const result = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    result.set(chunk, offset);
    offset += chunk.length;
  }
  return result;
}

// Await the 'drain' event on a backpressured stream before continuing.
// Falls back after 5000ms to avoid hanging indefinitely if the event never fires.
function awaitDrain(stream: Stream): Promise<void> {
  return new Promise(resolve => {
    const timer = setTimeout(resolve, 5000);
    stream.addEventListener('drain', () => { clearTimeout(timer); resolve(); }, { once: true });
  });
}

// Write a raw proto message and half-close the write side so the remote's
// io.ReadAll (or equivalent) terminates.
export async function writeMessage(stream: Stream, data: Uint8Array): Promise<void> {
  const ok = stream.send(data);
  if (ok === false) await awaitDrain(stream);
  await stream.close();
}

// Read all bytes from the stream until the remote half-closes its write side.
export async function readMessage(stream: Stream): Promise<Uint8Array> {
  const data = await readAll(stream);
  if (data.length === 0) throw new Error('stream closed with no data');
  return data;
}

// Write request, half-close write side, then read response.
// Concurrent send+read avoids deadlock when the remote reads before responding.
export async function sendAndReceive(stream: Stream, request: Uint8Array): Promise<Uint8Array> {
  // Start reading BEFORE closing write so buffers don't stall.
  const readPromise = readAll(stream);
  const ok = stream.send(request);
  if (ok === false) await awaitDrain(stream);
  await stream.close(); // half-close write — remote's io.ReadAll terminates
  const data = await readPromise;
  if (data.length === 0) throw new Error('stream closed with no response');
  return data;
}
