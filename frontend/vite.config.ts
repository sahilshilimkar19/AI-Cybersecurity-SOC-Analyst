/// <reference types="vitest/config" />
import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

/**
 * The API base URL is injected at build time rather than hard-coded, so one
 * built artifact is not pinned to one environment. It has no default: a bundle
 * that silently falls back to some other host is a bundle that can send an
 * analyst's bearer token somewhere nobody chose.
 */
export default defineConfig({
  plugins: [react()],
  build: {
    outDir: 'dist',
    sourcemap: true,
  },
  test: {
    globals: true,
    environment: 'jsdom',
    setupFiles: ['./src/test/setup.ts'],
    css: false,
    coverage: {
      provider: 'v8',
      reporter: ['text', 'html'],
      include: ['src/**/*.{ts,tsx}'],
      exclude: [
        'src/main.tsx',
        'src/test/**',
        'src/**/*.test.{ts,tsx}',
        // Declaration-only: no runtime statements to cover, and counting them
        // would let real gaps hide behind a comfortable percentage.
        'src/**/*.d.ts',
        'src/api/types.ts',
      ],
    },
  },
})
