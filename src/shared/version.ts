import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const packageJson = loadPackageJson();

export const PACKAGE_VERSION = packageJson.version ?? '0.0.0';

function loadPackageJson(): { version?: string } {
  try {
    return require('../../package.json') as { version?: string };
  } catch {
    return require('../package.json') as { version?: string };
  }
}
