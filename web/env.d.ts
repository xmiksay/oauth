/// <reference types="vite/client" />

/** `SYSTEM_TENANT_SLUG` from the repository's `.env` under the Vite dev server; else `system`. */
declare const __SYSTEM_TENANT_SLUG__: string
/** `APEX_TENANT` from the repository's `.env` under the Vite dev server; else `''` (= unset). */
declare const __APEX_TENANT__: string
