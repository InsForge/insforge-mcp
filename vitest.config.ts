import { defineConfig } from 'vitest/config';

// Inspect CLI args to detect if integration tests are being explicitly run
const isIntegrationOnly = process.argv.some(arg => 
  arg.replace(/\\/g, '/').includes('src/integration')
);

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    include: ['src/**/*.test.ts'],
    exclude: isIntegrationOnly ? [] : ['src/integration/**'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html'],
      exclude: ['node_modules/', 'dist/'],
    },
    server: {
      deps: {
        inline: [/@insforge\/shared-schemas/],
      },
    },
  },
});
