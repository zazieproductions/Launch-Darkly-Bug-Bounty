/**
 * Type-only stub for js-core's `packages/shared/common/src/api/context/**` interface files and the
 * `src/api` barrel.
 *
 * WHY THIS EXISTS (and why it provably cannot change behaviour)
 *   Those files declare TypeScript *types only*. Two of the files we execute import them with a
 *   bare `import { X } from './api...'` rather than `import type { X }`:
 *     - AttributeReference.ts:1  import { LDContextCommon } from './api/context/LDContextCommon'
 *     - ContextFilter.ts:4       import { LDContextCommon } from './api'
 *   Node's TypeScript transform cannot prove such a binding is a type, so it does not erase it and
 *   module instantiation fails on nested type-only imports.
 *
 *   Evidence the stub is runtime-neutral:
 *     1. `grep -rnE '^\s*(export\s+)?(abstract\s+)?(class|function|const|let|var|enum)\s' \
 *         packages/shared/common/src/api/context/`  -> NO MATCHES (exit 1). The subtree contains
 *         interfaces/type aliases only; there is no executable code to replace.
 *     2. Its complete export set is exactly the six names below.
 *     3. Every one of those names is used only in type positions by the files under test.
 *   Binding them to `undefined` therefore cannot affect execution. No vendor logic is substituted:
 *   the reference parser (AttributeReference.ts), the redaction algorithm (ContextFilter.ts) and the
 *   canonical-key logic (Context.ts) all run as real, unmodified vendor source.
 */
export const LDContext = undefined;
export const LDContextCommon = undefined;
export const LDContextMeta = undefined;
export const LDMultiKindContext = undefined;
export const LDSingleKindContext = undefined;
export const LDUser = undefined;
