#!/usr/bin/env bash
set -euo pipefail

# wsocket build script

cmd="${1:-build}"

case "$cmd" in
  build)
    mkdir -p bin
    odin build examples/ -out:bin/wsocket-example
    ;;
  run)
    mkdir -p bin
    odin build examples/ -out:bin/wsocket-example
    ./bin/wsocket-example
    ;;
  test)
    odin test tests/
    ;;
  test:integration)
    mkdir -p bin
    odin build examples/ -out:bin/wsocket-example
    python3 tests/integration_test.py
    ;;
  check)
    odin check . -no-entry-point
    ;;
  fmt)
    for f in *.odin examples/*.odin tests/*.odin; do
      odinfmt -w "$f"
    done
    ;;
  *)
    echo "Usage: $0 {build|run|test|test:integration|check|fmt}" >&2
    exit 1
    ;;
esac
