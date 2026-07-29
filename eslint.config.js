import js from '@eslint/js';
import tseslint from 'typescript-eslint';

export default tseslint.config(
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    ignores: ['dist/**', 'node_modules/**', 'eslint-runner.js', 'eslint-output.txt'],
  },
  {
    // Standalone operational scripts: plain ESM run directly by node, so the
    // runtime globals aren't in scope from the TypeScript config.
    files: ['scripts/**/*.mjs'],
    languageOptions: {
      globals: {
        process: 'readonly',
        console: 'readonly',
        fetch: 'readonly',
        URL: 'readonly',
        setTimeout: 'readonly',
      },
    },
  },
  {
    rules: {
      'no-console': 'off', // Allow console logging in MCP/HTTP servers
      '@typescript-eslint/no-explicit-any': 'warn',
      '@typescript-eslint/no-unused-vars': ['warn', { argsIgnorePattern: '^_' }],
    },
  }
);
