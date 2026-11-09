/// <reference types="vite/client" />

interface ImportMetaEnv {
  /**
   * Base URL of the ThreatPulse public CTI API.
   *
   * Development: `/api/cti/v1/` (served through the Vite proxy declared in
   * vite.config.ts). Production: `/api/cti/v1/` on the same origin.
   */
  readonly VITE_API_BASE_URL?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
