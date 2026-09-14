import { register } from 'node:module';
// import.meta.url is already an absolute file:// URL; use it as the parent base.
register('./ts-resolve-hook.mjs', import.meta.url);
