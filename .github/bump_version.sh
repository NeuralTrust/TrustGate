#!/bin/bash
# bump_version.sh

set -e

# Get current version from Go file
current_version=$(grep 'Version = "' internal/version/version.go | cut -d '"' -f2)
IFS='.' read -r major minor patch <<< "${current_version}"

# Bump patch version (you can make this configurable)
new_version="${major}.${minor}.$((patch + 1))"

# Update version in Go file
sed -i "s/Version = \".*\"/Version = \"${new_version}\"/" internal/version/version.go

# Commit and tag
git config user.name "ci-bot"
git config user.email "ci@yourdomain.com"
git commit -am "chore: bump version to ${new_version}"
git tag "v${new_version}"
git push origin main --tags
