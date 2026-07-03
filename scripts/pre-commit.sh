#!/bin/sh
echo "Running pre-commit hook..."

echo "Checking comment policy..."
HOOK_DIR=$(dirname "$0")
if [ -x "$HOOK_DIR/../../scripts/check-comments.sh" ]; then
  CHECK_COMMENTS="$HOOK_DIR/../../scripts/check-comments.sh"
else
  CHECK_COMMENTS="scripts/check-comments.sh"
fi
if [ -f "$CHECK_COMMENTS" ]; then
  sh "$CHECK_COMMENTS"
  if [ $? -ne 0 ]; then
    echo "Comment policy check failed!"
    exit 1
  fi
fi

make lint
if [ $? -ne 0 ]; then
  echo "Linting failed!"
  exit 1
fi

echo "Running Gosec Security Scanner..."
if ! command -v gosec >/dev/null 2>&1; then
  echo "gosec not found, installing..."
  go install github.com/securego/gosec/v2/cmd/gosec@latest
fi

gosec -severity high -exclude-generated ./...
if [ $? -ne 0 ]; then
  echo "Gosec found security issues!"
  exit 1
fi

make test
if [ $? -ne 0 ]; then
  echo "Tests failed!"
  exit 1
fi

echo "Pre-commit hook passed successfully!"
