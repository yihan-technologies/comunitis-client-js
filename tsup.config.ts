import { defineConfig } from 'tsup'

export default defineConfig({
  entry: ['src/index.ts'],
  format: ['cjs', 'esm'],
  dts: true,
  // netmask is CJS-only; bundle it inline so browser ESM consumers don't break
  noExternal: ['netmask'],
})
