#!/bin/sh
# Build the WASM engine for the PWA and stage the OCR models.
# Run from pwa/ (`npm run build:wasm`) or repo root.
set -e
cd "$(dirname "$0")/../.."

wasm-pack build crates/wasm \
  --target web \
  --out-dir ../../pwa/src/wasm \
  --out-name pdfsan_wasm

mkdir -p pwa/public/models
for name in text-detection text-recognition; do
  src=""
  for ext in rten onnx; do
    if [ -f "tests/fixtures/models/$name.$ext" ]; then
      src="tests/fixtures/models/$name.$ext"
      break
    fi
  done
  if [ -z "$src" ]; then
    src="$HOME/.cache/pdf-sanitizer/models/$name.rten"
    [ -f "$src" ] || src="$HOME/.cache/pdf-sanitizer/models/$name.onnx"
  fi
  cp "$src" "pwa/public/models/$(basename "$src")"
done

echo "wasm + models staged in pwa/"
