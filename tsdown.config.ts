import { defineConfig } from 'tsdown';

export default defineConfig({
  entry: {
    'core/index': 'src/core/index.ts',
    'strength/index': 'src/strength/index.ts',
    'breach/index': 'src/breach/index.ts',
    'crypto/index': 'src/crypto/index.ts',
    'passkey/index': 'src/passkey/index.ts',
    'react/index': 'src/react/index.ts',
  },
  format: ['esm', 'cjs'],
  dts: { oxc: true },
  platform: 'neutral',
  fixedExtension: true,
  treeshake: true,
  deps: {
    neverBundle: ['react'],
  },
});
