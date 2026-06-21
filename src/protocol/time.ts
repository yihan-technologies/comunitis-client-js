// Encodes a Date as 8 bytes little-endian Unix milliseconds,
// matching Go's binary.LittleEndian.PutUint64(buf, uint64(t.UnixMilli())).
export function encodeTime(date: Date = new Date()): Uint8Array {
  const ms = BigInt(date.getTime());
  const buf = new Uint8Array(8);
  const view = new DataView(buf.buffer);
  view.setBigUint64(0, ms, true); // true = little-endian
  return buf;
}

export function decodeTime(buf: Uint8Array): Date {
  const view = new DataView(buf.buffer, buf.byteOffset, 8);
  const ms = view.getBigUint64(0, true);
  return new Date(Number(ms));
}
