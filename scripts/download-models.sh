#!/bin/sh
# One-time bootstrap download of the ocrs OCR models (pure-rten Latin models).
# All document processing is 100% offline; this is the only network access.
# Usage: scripts/download-models.sh [target-dir]
set -e
DIR="${1:-tests/fixtures/models}"
mkdir -p "$DIR"
BASE="https://ocrs-models.s3-accelerate.amazonaws.com"

fetch() {
    name="$1"
    if [ -f "$DIR/$name.rten" ] || [ -f "$DIR/$name.onnx" ]; then
        echo "already present: $name"
        return
    fi
    echo "downloading $name.rten"
    if ! curl -fL "$BASE/$name.rten" -o "$DIR/$name.rten"; then
        echo "rten variant unavailable, falling back to onnx"
        curl -fL "$BASE/$name.onnx" -o "$DIR/$name.onnx"
    fi
}

fetch text-detection
fetch text-recognition
echo "models ready in $DIR"
