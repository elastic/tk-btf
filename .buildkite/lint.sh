#!/bin/bash
set -euo pipefail

go mod tidy
git diff --exit-code

make write-license-headers
git diff --exit-code

make notice
git diff --exit-code

golangci-lint run -v --timeout=600s
