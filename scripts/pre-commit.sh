#!/bin/sh
echo "Running pre-commit hook..."

make lint
if [ $? -ne 0 ]; then
  echo "Linting failed!"
  exit 1
fi

echo "Running Gosec Security Scanner..."
if ! command -v gosec &> /dev/null; then
  echo "gosec not found, installing..."
  go install github.com/securego/gosec/v2/cmd/gosec@latest
fi

gosec -no-fail ./...
if [ $? -ne 0 ]; then
  echo "Gosec found security issues (non-blocking due to -no-fail)"
fi

make test
if [ $? -ne 0 ]; then
  echo "Tests failed!"
  exit 1
fi

echo "Pre-commit hook passed successfully!"
