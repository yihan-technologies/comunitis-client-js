import { signBytes, verifyBytes } from '../keymanager/crypto.js';
import { encodeTime } from './time.js';

// requestSignBytes builds the message that gets Ed25519-signed for a TransferSingle request.
// Matches: Sign(RequestID_utf8 || Time_8bytes_LE || Data_bytes)
export function requestSignBytes(requestId: string, time: Uint8Array, data: Uint8Array): Uint8Array {
  const idBytes = new TextEncoder().encode(requestId);
  const msg = new Uint8Array(idBytes.length + 8 + data.length);
  msg.set(idBytes, 0);
  msg.set(time, idBytes.length);
  msg.set(data, idBytes.length + 8);
  return msg;
}

// responseSignBytes builds the message verified for a Response.
// Matches: Sign(RequestID_utf8 || Time_8bytes_LE || Data_bytes || ErrCode_4bytes_LE || ErrString_utf8)
export function responseSignBytes(
  requestId: string,
  time: Uint8Array,
  data: Uint8Array,
  errCode?: number,
  errStr?: string,
): Uint8Array {
  const idBytes = new TextEncoder().encode(requestId);
  const errStrBytes = errStr ? new TextEncoder().encode(errStr) : new Uint8Array(0);
  const errCodeBytes = new Uint8Array(4);
  if (errCode != null) new DataView(errCodeBytes.buffer).setUint32(0, errCode, true);

  const msg = new Uint8Array(idBytes.length + 8 + data.length + 4 + errStrBytes.length);
  let off = 0;
  msg.set(idBytes, off); off += idBytes.length;
  msg.set(time, off); off += 8;
  msg.set(data, off); off += data.length;
  msg.set(errCodeBytes, off); off += 4;
  msg.set(errStrBytes, off);
  return msg;
}

export function signRequest(priv64: Uint8Array, requestId: string, data: Uint8Array): { time: Uint8Array; signature: Uint8Array } {
  const time = encodeTime();
  const msg = requestSignBytes(requestId, time, data);
  const signature = signBytes(priv64, msg);
  return { time, signature };
}

export function signResponse(priv64: Uint8Array, requestId: string, time: bigint, data: Uint8Array): Uint8Array {
  const timeBuf = new Uint8Array(8);
  new DataView(timeBuf.buffer).setBigInt64(0, time, true);
  const msg = responseSignBytes(requestId, timeBuf, data);
  return signBytes(priv64, msg);
}

export function verifyResponse(
  pub: Uint8Array,
  requestId: string,
  time: Uint8Array,
  data: Uint8Array,
  signature: Uint8Array,
  errCode?: number,
  errStr?: string,
): boolean {
  const msg = responseSignBytes(requestId, time, data, errCode, errStr);
  return verifyBytes(pub, msg, signature);
}
