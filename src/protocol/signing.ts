import { signBytes, verifyBytes } from '../keymanager/crypto.js';
import { encodeTime } from './time.js';
import { AccountKeySelfServiceAction } from '../proto/index_pb.js';

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
// Matches Go's SignResponseIndex exactly:
//   Sign(RequestID_utf8 || Time_8bytes_LE || Data_bytes
//        [|| ErrCode_4bytes_LE]  // only when errCode is present and non-zero
//        [|| ErrString_utf8])    // only when errStr is present and non-empty
export function responseSignBytes(
  requestId: string,
  time: Uint8Array,
  data: Uint8Array,
  errCode?: number,
  errStr?: string,
): Uint8Array {
  const idBytes = new TextEncoder().encode(requestId);
  const includeErrCode = errCode != null && errCode !== 0;
  const errStrBytes = (errStr != null && errStr !== '') ? new TextEncoder().encode(errStr) : new Uint8Array(0);

  const msg = new Uint8Array(
    idBytes.length + 8 + data.length
    + (includeErrCode ? 4 : 0)
    + errStrBytes.length,
  );
  let off = 0;
  msg.set(idBytes, off); off += idBytes.length;
  msg.set(time, off); off += 8;
  msg.set(data, off); off += data.length;
  if (includeErrCode) {
    new DataView(msg.buffer).setUint32(off, errCode, true); off += 4;
  }
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

// buildAccountKeySigPayload builds the canonical inner-sig payload for ACCOUNT_KEY_SELF_SERVICE.
// Must mirror Go's buildInnerSigPayload in db/p2p_entry_account_key.go exactly.
export function buildAccountKeySigPayload(
  accountID: bigint,
  action: AccountKeySelfServiceAction,
  isPrivate: boolean,
  extra: { newPubKey?: Uint8Array; targetKeyID?: bigint; permSpec?: string },
): Uint8Array {
  const parts: Uint8Array[] = [];

  const accBuf = new Uint8Array(8);
  new DataView(accBuf.buffer).setBigUint64(0, accountID, false); // BE
  parts.push(accBuf);

  const actBuf = new Uint8Array(4);
  new DataView(actBuf.buffer).setUint32(0, action, true); // LE
  parts.push(actBuf);

  parts.push(new Uint8Array([isPrivate ? 0x01 : 0x00]));

  if (action === AccountKeySelfServiceAction.AK_ADD_PUBKEY && extra.newPubKey) {
    parts.push(extra.newPubKey);
  } else if (action === AccountKeySelfServiceAction.AK_UPDATE_PERMISSION) {
    const tgt = new Uint8Array(8);
    new DataView(tgt.buffer).setBigUint64(0, extra.targetKeyID!, false); // BE
    parts.push(tgt);
    parts.push(new TextEncoder().encode(extra.permSpec ?? ''));
  } else if (action === AccountKeySelfServiceAction.AK_DISABLE_PUBKEY) {
    const tgt = new Uint8Array(8);
    new DataView(tgt.buffer).setBigUint64(0, extra.targetKeyID!, false); // BE
    parts.push(tgt);
  }

  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) { out.set(p, off); off += p.length; }
  return out;
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
