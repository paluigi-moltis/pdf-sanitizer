/// <reference lib="webworker" />
// Sanitizer Web Worker: loads the WASM engine + OCR models (cached in
// IndexedDB after the first fetch) and runs the whole dual-path pipeline
// off the UI thread. No document bytes ever leave the browser.

import init, { SanitizerWasm, synth_benign_pdf, synth_hostile_pdf } from './wasm/pdfsan_wasm';
import { get, set } from 'idb-keyval';
import type { PageImage, WorkerRequest, WorkerResponse } from './types';

let sanitizer: SanitizerWasm | null = null;

const post = (msg: WorkerResponse, transfer: Transferable[] = []) =>
  (self as unknown as Worker).postMessage(msg, transfer);

const MODELS = {
  detection: '/models/text-detection.onnx',
  recognition: '/models/text-recognition.onnx',
};

async function fetchModel(url: string): Promise<Uint8Array> {
  // Cache Storage (via Workbox) already serves the model offline once the
  // service worker is active; IndexedDB gives us a worker-side fallback.
  const key = `model:${url}`;
  const cached = await get<Uint8Array>(key);
  if (cached) return cached;

  const res = await fetch(url);
  if (!res.ok) throw new Error(`fetch ${url} -> ${res.status}`);
  const bytes = new Uint8Array(await res.arrayBuffer());
  await set(key, bytes);
  return bytes;
}

async function ensureSanitizer(): Promise<SanitizerWasm> {
  if (sanitizer) return sanitizer;
  post({ type: 'status', message: 'Loading OCR models…' });
  const [detection, recognition] = await Promise.all([
    fetchModel(MODELS.detection),
    fetchModel(MODELS.recognition),
  ]);
  post({ type: 'status', message: 'Starting WASM engine…' });
  sanitizer = new SanitizerWasm(detection, recognition);
  return sanitizer;
}

self.onmessage = async (event: MessageEvent<WorkerRequest>) => {
  const msg = event.data;
  try {
    if (msg.type === 'init') {
      await init();
      await ensureSanitizer();
      post({ type: 'ready' });
      return;
    }

    if (msg.type === 'demo') {
      const engine = await ensureSanitizer();
      const bytes = msg.hostile ? synth_hostile_pdf() : synth_benign_pdf();
      runSanitize(engine, msg.hostile ? 'hostile-demo.pdf' : 'benign-demo.pdf', bytes);
      return;
    }

    if (msg.type === 'sanitize') {
      const engine = await ensureSanitizer();
      runSanitize(engine, msg.filename, new Uint8Array(msg.bytes));
      return;
    }
  } catch (err) {
    post({ type: 'error', message: err instanceof Error ? err.message : String(err) });
  }
};

function runSanitize(engine: SanitizerWasm, filename: string, bytes: Uint8Array): void {
  try {
    const onProgress = (done: number, total: number) =>
      post({ type: 'progress', done, total });

    const result = engine.sanitize(bytes, filename, onProgress) as {
      report: unknown;
      pageImages: { pageNumber: number; width: number; height: number; rgba: Uint8Array }[];
    };

    const pageImages: PageImage[] = result.pageImages.map((img) => ({
      pageNumber: img.pageNumber,
      width: img.width,
      height: img.height,
      rgba: img.rgba.slice(), // copy out of wasm memory
    }));

    post(
      {
        type: 'result',
        report: result.report as import('./types').Report,
        pageImages,
      },
      pageImages.map((img) => img.rgba.buffer),
    );
  } catch (err) {
    post({ type: 'error', message: err instanceof Error ? err.message : String(err) });
  }
}
