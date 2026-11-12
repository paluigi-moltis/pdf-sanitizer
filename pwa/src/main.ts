// pdf-sanitizer PWA entry point: offline, client-side split-pane report UI.
// All processing happens in the sanitizer Web Worker (see worker.ts).

import './style.css';
import type { Finding, PageImage, Report, WorkerRequest, WorkerResponse } from './types';

const app = document.getElementById('app')!;

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

let report: Report | null = null;
let pageImages: PageImage[] = [];
let activeTab: 'findings' | 'markdown' = 'findings';

// ---------------------------------------------------------------------------
// Worker wiring
// ---------------------------------------------------------------------------

const worker = new Worker(new URL('./worker.ts', import.meta.url), { type: 'module' });

worker.onmessage = (event: MessageEvent<WorkerResponse>) => {
  const msg = event.data;
  switch (msg.type) {
    case 'status':
      setStatus(msg.message);
      break;
    case 'ready':
      setStatus('Engine ready — drop a PDF or try a demo');
      enableInputs(true);
      break;
    case 'progress':
      setProgress(msg.done, msg.total);
      break;
    case 'result':
      report = msg.report;
      pageImages = msg.pageImages;
      setStatus('');
      setProgress(0, 0);
      render();
      break;
    case 'error':
      setStatus(`Error: ${msg.message}`);
      setProgress(0, 0);
      enableInputs(true);
      break;
  }
};

worker.onerror = (e) => setStatus(`Worker error: ${e.message}`);

function send(msg: WorkerRequest, transfer: Transferable[] = []): void {
  enableInputs(false);
  worker.postMessage(msg, transfer);
}

// ---------------------------------------------------------------------------
// Header / upload
// ---------------------------------------------------------------------------

function h(
  tag: string,
  attrs: Record<string, string | (() => void)>,
  ...children: (Node | string)[]
) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (typeof v === 'function') el.addEventListener(k.replace(/^on/, ''), v as EventListener);
    else if (k === 'class') el.className = v;
    else if (k === 'text') el.textContent = v;
    else el.setAttribute(k, v);
  }
  for (const c of children)
    el.appendChild(typeof c === 'string' ? document.createTextNode(c) : c);
  return el;
}

function renderHeader(): HTMLElement {
  const fileInput = h('input', { type: 'file', accept: 'application/pdf', class: 'hidden' }) as HTMLInputElement;
  fileInput.addEventListener('change', () => {
    const file = fileInput.files?.[0];
    if (file) void loadFile(file);
  });

  const drop = h(
    'div',
    {
      class:
        'flex-1 rounded-lg border border-slate-700 bg-slate-900/60 px-4 py-3 text-sm text-slate-300',
      text: 'Drop a PDF here — files never leave your device',
    },
  );

  const dropzone = h(
    'div',
    { class: 'flex items-center gap-3' },
    drop,
    h('button', {
      class:
        'rounded-md bg-sky-600 px-3 py-2 text-sm font-medium text-white hover:bg-sky-500 disabled:opacity-50',
      text: 'Choose PDF',
      onclick: () => fileInput.click(),
      id: 'btn-choose',
    }),
    h('button', {
      class:
        'rounded-md border border-rose-700 bg-rose-950/60 px-3 py-2 text-sm font-medium text-rose-300 hover:bg-rose-900/60 disabled:opacity-50',
      text: 'Hostile demo',
      onclick: () => send({ type: 'demo', hostile: true }),
      id: 'btn-hostile',
    }),
    h('button', {
      class:
        'rounded-md border border-emerald-700 bg-emerald-950/60 px-3 py-2 text-sm font-medium text-emerald-300 hover:bg-emerald-900/60 disabled:opacity-50',
      text: 'Benign demo',
      onclick: () => send({ type: 'demo', hostile: false }),
      id: 'btn-benign',
    }),
    fileInput,
  );

  dropzone.addEventListener('dragover', (e) => {
    e.preventDefault();
    drop.classList.add('dropzone-active');
  });
  dropzone.addEventListener('dragleave', () => drop.classList.remove('dropzone-active'));
  dropzone.addEventListener('drop', (e) => {
    e.preventDefault();
    drop.classList.remove('dropzone-active');
    const file = e.dataTransfer?.files?.[0];
    if (file) void loadFile(file);
  });

  return h(
    'header',
    { class: 'border-b border-slate-800 bg-slate-900/80 px-4 py-3' },
    h(
      'div',
      { class: 'mx-auto flex max-w-7xl flex-col gap-3' },
      h(
        'div',
        { class: 'flex items-baseline justify-between' },
        h('h1', {
          class: 'text-lg font-semibold tracking-tight',
          text: 'pdf-sanitizer',
        }),
        h('span', {
          class: 'text-xs text-slate-500',
          text: 'offline · prompt-injection detector · WYSIWYG sanitizer',
        }),
      ),
      dropzone,
      h(
        'div',
        { class: 'flex items-center gap-3' },
        h('div', { id: 'status', class: 'text-xs text-slate-400' }),
        progressBar(),
      ),
    ),
  );
}

function progressBar(): HTMLElement {
  return h('div', { class: 'h-1.5 flex-1 overflow-hidden rounded bg-slate-800' }, h('div', { id: 'progress', class: 'h-full w-0 rounded bg-sky-500 transition-all' }));
}

function setStatus(text: string): void {
  const el = document.getElementById('status');
  if (el) el.textContent = text;
}

function setProgress(done: number, total: number): void {
  const el = document.getElementById('progress');
  if (!el) return;
  el.style.width = total > 0 ? `${(done / total) * 100}%` : '0%';
  if (total > 0 && done < total) setStatus(`Scanning page ${done}/${total}…`);
}

function enableInputs(enabled: boolean): void {
  for (const id of ['btn-choose', 'btn-hostile', 'btn-benign']) {
    const el = document.getElementById(id) as HTMLButtonElement | null;
    if (el) el.disabled = !enabled;
  }
}

async function loadFile(file: File): Promise<void> {
  const buf = await file.arrayBuffer();
  send({ type: 'sanitize', filename: file.name, bytes: buf }, [buf]);
}

// ---------------------------------------------------------------------------
// Report rendering
// ---------------------------------------------------------------------------

const SEV_STYLE: Record<string, string> = {
  critical: 'bg-rose-500/15 text-rose-300 border-rose-500/50',
  high: 'bg-orange-500/15 text-orange-300 border-orange-500/50',
  medium: 'bg-yellow-500/15 text-yellow-200 border-yellow-500/50',
  low: 'bg-sky-500/15 text-sky-300 border-sky-500/50',
};

const RISK_STYLE: Record<string, string> = {
  high: 'bg-rose-600',
  medium: 'bg-orange-600',
  low: 'bg-yellow-600',
  none: 'bg-emerald-600',
};

function renderPagePane(): HTMLElement {
  const pane = h('section', {
    class: 'flex-1 overflow-y-auto bg-slate-900/40 p-4',
    id: 'pane-pages',
  });
  if (pageImages.length === 0) {
    pane.appendChild(
      h('p', {
        class: 'pt-16 text-center text-sm text-slate-600',
        text: 'No document scanned yet.',
      }),
    );
    return pane;
  }
  for (const img of pageImages) {
    const holder = h('div', {
      class: 'relative mx-auto mb-6 w-fit max-w-full shadow-xl ring-1 ring-slate-700',
      'data-page': String(img.pageNumber),
    });
    const canvas = document.createElement('canvas');
    canvas.width = img.width;
    canvas.height = img.height;
    canvas.style.maxWidth = '100%';
    canvas.style.height = 'auto';
    canvas.style.display = 'block';
    const ctx = canvas.getContext('2d')!;
    // ImageData requires a Uint8ClampedArray; the worker sends a Uint8Array.
    const rgba = new Uint8ClampedArray(img.rgba);
    const imageData = new ImageData(rgba, img.width, img.height);
    ctx.putImageData(imageData, 0, 0);
    holder.appendChild(canvas);

    for (const f of report!.findings) {
      if (f.location.page !== img.pageNumber || !f.location.bbox_norm) continue;
      const [x0, y0, x1, y1] = f.location.bbox_norm;
      const box = h('button', {
        class: `absolute cursor-pointer border-2 sev-${f.severity}`,
        'data-finding': f.id,
        title: `${f.id} [${f.severity}] ${f.category}`,
        onclick: () => activateFinding(f.id),
      }) as HTMLButtonElement;
      box.style.left = `${x0 * 100}%`;
      box.style.top = `${y0 * 100}%`;
      box.style.width = `${Math.max((x1 - x0) * 100, 0.5)}%`;
      box.style.height = `${Math.max((y1 - y0) * 100, 0.5)}%`;
      holder.appendChild(box);
    }

    pane.appendChild(holder);
  }
  return pane;
}

function findingCard(f: Finding): HTMLElement {
  const card = h(
    'article',
    {
      class:
        'rounded-lg border border-slate-800 bg-slate-900/70 p-3 transition hover:border-slate-600',
      'data-finding-card': f.id,
    },
    h(
      'div',
      { class: 'flex items-center gap-2' },
      h(
        'span',
        { class: `rounded border px-1.5 py-0.5 text-[10px] font-bold uppercase ${SEV_STYLE[f.severity] ?? ''}` },
        f.severity,
      ),
      h('span', { class: 'text-xs font-mono text-slate-500', text: f.id }),
      h('span', { class: 'text-xs text-slate-400', text: f.category }),
    ),
    h(
      'p',
      { class: 'mt-2 text-xs leading-relaxed text-slate-300', text: f.reason },
    ),
    h(
      'div',
      { class: 'mt-2 flex flex-wrap items-center gap-x-3 gap-y-1 text-[11px] text-slate-500' },
      h('span', {
        text: f.location.page === 0 ? 'document-level' : `page ${f.location.page}`,
      }),
      h('span', { text: f.location.surface.replace(/_/g, ' ') }),
      h('span', { text: `action: ${f.action_taken}` }),
    ),
  );

  if (f.quarantined_snippet) {
    const details = h(
      'details',
      { class: 'group mt-2' },
      h('summary', {
        class: 'cursor-pointer text-[11px] text-sky-400 hover:text-sky-300',
        text: 'quarantined snippet',
      }),
      h(
        'pre',
        {
          class:
            'md-pre mt-1 max-h-40 overflow-auto rounded bg-black/40 p-2 text-[10px] text-rose-200',
          text: f.quarantined_snippet,
        },
      ),
    );
    card.appendChild(details);
  }

  card.addEventListener('click', (e) => {
    if ((e.target as HTMLElement).closest('details')) return;
    activateFinding(f.id);
  });
  return card;
}

function renderFindingsPane(): HTMLElement {
  const pane = h('section', {
    class: 'flex w-full max-w-xl flex-col overflow-y-auto border-l border-slate-800 bg-slate-950',
    id: 'pane-findings',
  });
  if (!report) {
    pane.appendChild(h('p', { class: 'p-6 text-sm text-slate-600', text: 'Nothing to show yet.' }));
    return pane;
  }
  const d = report.document;
  pane.appendChild(
    h(
      'div',
      { class: 'flex items-center justify-between border-b border-slate-800 p-3' },
      h('button', {
        class: `rounded px-2.5 py-1 text-xs font-bold uppercase tracking-wide text-white ${RISK_STYLE[d.risk_level] ?? 'bg-slate-600'}`,
        text: `${d.risk_level} risk`,
      }),
      h('span', {
        class: 'text-xs text-slate-400',
        text: `${d.filename} · ${d.page_count} page(s) · ${d.summary.total_findings} finding(s)`,
      }),
      h('span', {
        class: 'text-[11px] text-slate-500',
        text: `${d.summary.hidden_text_removed} hidden removed · ${d.summary.metadata_or_links_stripped} stripped`,
      }),
    ),
  );

  // Tabs
  const tabs = h(
    'div',
    { class: 'flex border-b border-slate-800 text-xs' },
    tabButton('findings', `Findings (${report.findings.length})`),
    tabButton('markdown', 'Sanitized Markdown'),
  );
  pane.appendChild(tabs);

  if (activeTab === 'findings') {
    const list = h('div', { class: 'flex flex-col gap-2 p-3' });
    if (report.findings.length === 0) {
      list.appendChild(
        h('p', { class: 'py-8 text-center text-sm text-emerald-400', text: '✓ No findings — document is clean.' }),
      );
    }
    for (const f of report.findings) list.appendChild(findingCard(f));
    pane.appendChild(list);
  } else {
    pane.appendChild(markdownTab());
  }
  return pane;
}

function tabButton(tab: 'findings' | 'markdown', label: string): HTMLElement {
  const active = activeTab === tab;
  return h('button', {
    class: `flex-1 px-3 py-2 font-medium ${active ? 'border-b-2 border-sky-500 text-sky-300' : 'text-slate-500 hover:text-slate-300'}`,
    text: label,
    onclick: () => {
      activeTab = tab;
      render();
    },
  });
}

function markdownTab(): HTMLElement {
  const wrap = h('div', { class: 'flex flex-col gap-3 p-3' });
  const actions = h(
    'div',
    { class: 'flex gap-2' },
    h('button', {
      class: 'rounded bg-slate-800 px-3 py-1.5 text-xs text-slate-200 hover:bg-slate-700',
      text: 'Copy Markdown',
      onclick: () => {
        void navigator.clipboard.writeText(report!.sanitized_markdown);
      },
    }),
    h('button', {
      class: 'rounded bg-slate-800 px-3 py-1.5 text-xs text-slate-200 hover:bg-slate-700',
      text: 'Download .md',
      onclick: () => download('sanitized.md', report!.sanitized_markdown, 'text/markdown'),
    }),
    h('button', {
      class: 'rounded bg-slate-800 px-3 py-1.5 text-xs text-slate-200 hover:bg-slate-700',
      text: 'Download .report.json',
      onclick: () =>
        download('report.json', JSON.stringify(report, null, 2), 'application/json'),
    }),
  );
  wrap.appendChild(actions);
  wrap.appendChild(
    h('pre', { class: 'md-pre flex-1 rounded bg-black/40 p-3 text-slate-200', text: report!.sanitized_markdown }),
  );
  return wrap;
}

function download(name: string, content: string, type: string): void {
  const url = URL.createObjectURL(new Blob([content], { type }));
  const a = document.createElement('a');
  a.href = url;
  a.download = name;
  a.click();
  URL.revokeObjectURL(url);
}

function activateFinding(id: string): void {
  if (activeTab !== 'findings') {
    activeTab = 'findings';
    render();
  }
  const card = document.querySelector(`[data-finding-card="${id}"]`);
  card?.scrollIntoView({ behavior: 'smooth', block: 'center' });
  const overlay = document.querySelector(`[data-finding="${id}"]`);
  overlay?.scrollIntoView({ behavior: 'smooth', block: 'center' });
  overlay?.classList.remove('overlay-flash');
  void (overlay as HTMLElement | null)?.offsetWidth; // reflow to restart animation
  overlay?.classList.add('overlay-flash');
}

// ---------------------------------------------------------------------------
// Root render
// ---------------------------------------------------------------------------

function render(): void {
  app.replaceChildren();
  app.appendChild(renderHeader());
  const main = h('main', { class: 'flex min-h-0 flex-1 flex-col lg:flex-row' });
  main.appendChild(renderPagePane());
  main.appendChild(renderFindingsPane());
  app.appendChild(main);
}

render();
setStatus('Loading WASM engine + OCR models…');
send({ type: 'init' });
