import { describe, it, expect } from 'vitest';
import { randomUUID } from './uuid.js';

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

describe('randomUUID', () => {
  it('returns a valid v4 UUID', () => {
    expect(randomUUID()).toMatch(UUID_RE);
  });

  it('returns unique values', () => {
    const ids = new Set(Array.from({ length: 100 }, () => randomUUID()));
    expect(ids.size).toBe(100);
  });
});
