#!/bin/sh
echo "Running pre-commit hook..."

# Check if version.go has been modified
if git diff --cached --name-only | grep -q "pkg/version/version.go"; then
  # Check if Version variable has been modified
  if ! git diff --cached -U0 pkg/version/version.go | grep -q "^+[[:space:]]*Version[[:space:]]*=[[:space:]]*\""; then
    echo "\033[0;33mWARNING: pkg/version/version.go has been modified but Version has not changed\033[0m"
  fi
fi

make lint
if [ $? -ne 0 ]; then
  echo "Linting failed!"
  exit 1
fi

make test
if [ $? -ne 0 ]; then
  echo "Tests failed!"
  exit 1
fi

echo "Pre-commit hook passed successfully!"