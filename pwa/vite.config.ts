import { defineConfig } from 'vite';
import tailwindcss from '@tailwindcss/vite';
import { VitePWA } from 'vite-plugin-pwa';

export default defineConfig({
  plugins: [
    tailwindcss(),
    VitePWA({
      registerType: 'autoUpdate',
      includeAssets: ['manifest.webmanifest', 'icons/*.svg'],
      workbox: {
        globPatterns: ['**/*.{js,css,html,svg,webmanifest,wasm,onnx,rten,woff2}'],
        // The OCR models (~12 MB) must be precached for offline use.
        maximumFileSizeToCacheInBytes: 32 * 1024 * 1024,
        navigateFallback: '/index.html',
      },
      manifest: {
        name: 'pdf-sanitizer',
        short_name: 'pdf-sanitizer',
        description:
          'Offline PDF prompt-injection detector & WYSIWYG sanitizer — all processing stays on your device',
        start_url: '/',
        display: 'standalone',
        background_color: '#0b1120',
        theme_color: '#0b1120',
        icons: [
          { src: '/icons/icon.svg', sizes: 'any', type: 'image/svg+xml', purpose: 'any' },
        ],
      },
    }),
  ],
  build: { target: 'es2022' },
  worker: { format: 'es' as const },
  server: {
    fs: { allow: ['..'] },
  },
});
