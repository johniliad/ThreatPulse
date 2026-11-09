import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';

/*
 * ThreatPulse frontend build configuration.
 *
 * Production output is static (dist/) and is deployed to cPanel next to the
 * PHP API, so the API is consumed same-origin via VITE_API_BASE_URL.
 *
 * During development the API is proxied to the deployed host. This is not
 * optional: publications.php returns no CORS headers, so a direct
 * cross-origin call from the dev server would be blocked by the browser.
 */

const API_TARGET = 'https://threatpulse.iliadis.net';

export default defineConfig({
  plugins: [react()],

  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: API_TARGET,
        changeOrigin: true,
        secure: true,
      },
    },
  },

  preview: {
    port: 4173,
  },

  build: {
    outDir: 'dist',
    target: 'es2022',
    sourcemap: false,
  },

  test: {
    environment: 'jsdom',
    setupFiles: ['./src/test/setup.ts'],
    include: ['src/**/*.test.{ts,tsx}'],
    css: false,
    restoreMocks: true,
  },
});
