/// <reference types="vite/client" />

/** `SYSTEM_TENANT_SLUG` from the repository's `.env` at build time (default `system`). */
declare const __SYSTEM_TENANT_SLUG__: string
/** `APEX_TENANT` from the repository's `.env` at build time (`''` = unset); dev apex only. */
declare const __APEX_TENANT__: string
