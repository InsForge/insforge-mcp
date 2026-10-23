import { defineConfig } from 'tsup';

export default defineConfig({
  entry: {
    index: 'src/stdio/index.ts',
    'http-server': 'src/http/server.ts',
  },
  format: ['esm'],
  banner: {
    js: '#!/usr/bin/env node',
  },
  noExternal: ['@insforge/shared-schemas'],
  external: ['@modelcontextprotocol/sdk', 'commander', 'node-fetch', 'zod', 'express', 'mixpanel'],
  clean: true,
});
