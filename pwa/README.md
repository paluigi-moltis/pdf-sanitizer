# pwa/ — Milestone 3 (not yet implemented)

Offline-first Progressive Web App (Vite + TypeScript + Tailwind):

- drag-and-drop PDF upload, all processing locally in a Web Worker via
  `crates/wasm`;
- split-pane report viewer: rendered page images with color-coded
  `bbox_norm` overlays on the left, summary banner + clickable finding cards
  (severity, page, surface, reason, expandable quarantined text) on the
  right;
- sanitized-Markdown tab with one-click copy and `.md` / `.report.json`
  downloads;
- Service Worker (Workbox) caching `.wasm` and `.rten` model files for full
  offline use.

Will be built in Milestone 3 per the project plan (see root README).
