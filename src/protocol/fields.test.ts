import { describe, it, expect } from 'vitest';
import { encodeFields, decodeFields, type FieldDef } from './fields.js';

describe('encodeFields / decodeFields', () => {
  it('roundtrips a single field', () => {
    const fields: FieldDef[] = [
      { fieldId: 1, updateType: 2, encryptionLevel: 0, value: new Uint8Array([10, 20, 30]) },
    ];
    const encoded = encodeFields(fields);
    const decoded = decodeFields(encoded);
    expect(decoded).toHaveLength(1);
    expect(decoded[0]!.fieldId).toBe(1);
    expect(decoded[0]!.updateType).toBe(2);
    expect(decoded[0]!.encryptionLevel).toBe(0);
    expect(decoded[0]!.value).toEqual(new Uint8Array([10, 20, 30]));
  });

  it('roundtrips multiple fields', () => {
    const fields: FieldDef[] = [
      { fieldId: 5, updateType: 1, encryptionLevel: 2, value: new Uint8Array([0xff, 0x00]) },
      { fieldId: 255, updateType: 0, encryptionLevel: 1, value: new Uint8Array(0) },
      { fieldId: 10, updateType: 3, encryptionLevel: 0, value: new Uint8Array([1, 2, 3, 4, 5]) },
    ];
    const encoded = encodeFields(fields);
    const decoded = decodeFields(encoded);
    expect(decoded).toHaveLength(3);
    for (let i = 0; i < 3; i++) {
      expect(decoded[i]!.fieldId).toBe(fields[i]!.fieldId);
      expect(decoded[i]!.updateType).toBe(fields[i]!.updateType);
      expect(decoded[i]!.encryptionLevel).toBe(fields[i]!.encryptionLevel);
      expect(decoded[i]!.value).toEqual(fields[i]!.value);
    }
  });

  it('returns empty for empty input', () => {
    expect(encodeFields([])).toEqual(new Uint8Array(0));
    expect(decodeFields(new Uint8Array(0))).toEqual([]);
  });

  it('field length header is little-endian 5 + valueLen', () => {
    const val = new Uint8Array([0xab, 0xcd]);
    const encoded = encodeFields([{ fieldId: 7, updateType: 0, encryptionLevel: 0, value: val }]);
    const view = new DataView(encoded.buffer);
    expect(view.getUint16(0, true)).toBe(7); // 5 + 2
  });

  it('throws on truncated/corrupt data', () => {
    const fields = encodeFields([
      { fieldId: 1, updateType: 0, encryptionLevel: 0, value: new Uint8Array([1, 2, 3]) },
    ]);
    // Truncate by 2 bytes — fieldLen header says 8 but only 6 bytes available.
    const truncated = fields.slice(0, fields.length - 2);
    expect(() => decodeFields(truncated)).toThrow('corrupt field data');
  });
});
