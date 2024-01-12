#!/bin/bash
set -euo pipefail

go test -cover -v -race github.com/elastic/tk-btf
