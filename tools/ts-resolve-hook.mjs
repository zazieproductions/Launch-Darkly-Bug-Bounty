/**
 * Minimal ESM resolver hook that lets Node's built-in TypeScript support
 * (--experimental-transform-types) import LaunchDarkly's REAL .ts sources
 * unmodified.
 *
 * js-core's source uses TypeScript's classic extensionless relative imports
 * (`./api`, `./AttributeReference`). Node's ESM resolver requires an explicit
 * extension, so without this hook every import of a real .ts file fails.
 *
 * This hook ONLY completes the extension; it never rewrites, patches or
 * transpiles file contents. Combined with --experimental-transform-types it
 * means the PoC executes the vendor's actual source bytes.
 *
 * Usage: node --experimental-transform-types --import ./tools/ts-register.mjs <script.mjs>
 */
import fs from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import path from 'node:path';

const TS_EXT = ['.ts', '.mts', '.cts'];

// The `src/api` barrel is types-only; redirect it to a documented type stub.
// See tools/ts-stub-api-types.mjs for the proof that this is runtime-neutral.
const API_STUB = new URL('./ts-stub-api-types.mjs', import.meta.url).href;
// Every file in these locations is an interface/type-alias declaration only (see the stub
// file for the grep evidence). They are redirected so real vendor logic files can execute.
const STUBBED = [
  '/packages/shared/common/src/api/index.ts',
  '/packages/shared/common/src/api/context/',
];


function tryCandidates(basePath) {
  for (const ext of TS_EXT) {
    const p = basePath + ext;
    if (fs.existsSync(p) && fs.statSync(p).isFile()) return p;
  }
  if (fs.existsSync(basePath) && fs.statSync(basePath).isDirectory()) {
    for (const idx of ['index.ts', 'index.mts']) {
      const p = path.join(basePath, idx);
      if (fs.existsSync(p)) return p;
    }
  }
  return null;
}

export async function resolve(specifier, context, nextResolve) {
  // Only touch relative specifiers that Node cannot resolve as written.
  if (specifier.startsWith('.') || specifier.startsWith('/')) {
    const parentPath = context.parentURL ? fileURLToPath(context.parentURL) : process.cwd();
    const basePath = path.resolve(path.dirname(parentPath), specifier);

    if (!path.extname(specifier)) {
      const hit = tryCandidates(basePath);
      if (hit) {
        if (STUBBED.some((sfx) => (sfx.endsWith('/') ? hit.includes(sfx) : hit.endsWith(sfx)))) {
          return { url: API_STUB, shortCircuit: true, format: 'module' };
        }
        return {
          url: pathToFileURL(hit).href,
          shortCircuit: true,
          format: 'module-typescript',
        };
      }
    }
  }
  return nextResolve(specifier, context);
}
