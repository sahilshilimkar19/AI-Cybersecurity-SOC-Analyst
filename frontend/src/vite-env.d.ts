/// <reference types="vite/client" />

/**
 * Build-time configuration.
 *
 * `VITE_API_BASE_URL` is required in every environment: a bundle that silently
 * falls back to some other host is one that can send an analyst's bearer token
 * somewhere nobody chose. It is declared optional here because TypeScript
 * describes what `import.meta.env` *may* hold, and the client checks for it at
 * runtime rather than trusting the type.
 */
interface ImportMetaEnv {
  readonly VITE_API_BASE_URL?: string
}

interface ImportMeta {
  readonly env: ImportMetaEnv
}
