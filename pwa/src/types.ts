// Shared types between the UI thread and the sanitizer Web Worker.

export type Severity = 'critical' | 'high' | 'medium' | 'low';

export interface Location {
  page: number;
  surface: string;
  bbox_norm?: [number, number, number, number];
  object_ref?: string;
}

export interface Finding {
  id: string;
  severity: Severity;
  category: string;
  reason: string;
  action_taken: string;
  location: Location;
  quarantined_snippet?: string;
}

export interface Report {
  document: {
    filename: string;
    page_count: number;
    risk_level: 'none' | 'low' | 'medium' | 'high';
    summary: {
      total_findings: number;
      hidden_text_removed: number;
      metadata_or_links_stripped: number;
    };
  };
  findings: Finding[];
  sanitized_markdown: string;
}

export interface PageImage {
  pageNumber: number;
  width: number;
  height: number;
  rgba: Uint8Array;
}

export type WorkerRequest =
  | { type: 'init' }
  | { type: 'sanitize'; filename: string; bytes: ArrayBuffer }
  | { type: 'demo'; hostile: boolean };

export type WorkerResponse =
  | { type: 'status'; message: string }
  | { type: 'ready' }
  | { type: 'progress'; done: number; total: number }
  | { type: 'result'; report: Report; pageImages: PageImage[] }
  | { type: 'error'; message: string };
