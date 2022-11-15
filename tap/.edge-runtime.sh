#!/bin/bash

EDGE_RUNTIME_VERSION=$(npm ls --global --json | jq '.dependencies."edge-runtime".version')

./node_modules/.bin/esbuild \
  --log-level=warning \
  --format=esm \
  --bundle \
  --define:EDGE_RUNTIME_VERSION=$EDGE_RUNTIME_VERSION \
  --minify-syntax \
  --target=esnext \
  --outfile=tap/run-edge-runtime.js \
  tap/run-edge-runtime.ts

NODE_PATH=$(npm root -g) node tap/.edge-runtime.mjs
