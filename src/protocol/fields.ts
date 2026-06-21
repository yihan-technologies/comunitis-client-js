// Binary field encoding matching the Go storage format.
//
// Each field entry: FieldLen(2 LE) | FieldID(1) | UpdateType(1) | EncryptionLevel(1) | Value(N)
// FieldLen = 5 + len(Value) (includes the 5-byte header)

export interface FieldDef {
  fieldId: number;       // uint8
  updateType: number;    // uint8
  encryptionLevel: number; // uint8
  value: Uint8Array;
}

export function encodeFields(fields: FieldDef[]): Uint8Array {
  let totalLen = 0;
  for (const f of fields) totalLen += 5 + f.value.length;

  const buf = new Uint8Array(totalLen);
  const view = new DataView(buf.buffer);
  let offset = 0;

  for (const f of fields) {
    const fieldLen = 5 + f.value.length;
    view.setUint16(offset, fieldLen, true); // little-endian
    buf[offset + 2] = f.fieldId;
    buf[offset + 3] = f.updateType;
    buf[offset + 4] = f.encryptionLevel;
    buf.set(f.value, offset + 5);
    offset += fieldLen;
  }

  return buf;
}

export function decodeFields(data: Uint8Array): FieldDef[] {
  const fields: FieldDef[] = [];
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  let index = 0;

  while (index < data.length) {
    const fieldLen = view.getUint16(index, true);
    if (fieldLen < 5) {
      throw new Error(`corrupt field data: invalid fieldLen ${fieldLen} at offset ${index}`);
    }
    if (index + fieldLen > data.length) {
      throw new Error(`corrupt field data: fieldLen ${fieldLen} exceeds buffer at offset ${index}`);
    }
    fields.push({
      fieldId: data[index + 2]!,
      updateType: data[index + 3]!,
      encryptionLevel: data[index + 4]!,
      value: data.slice(index + 5, index + fieldLen),
    });
    index += fieldLen;
  }

  return fields;
}
