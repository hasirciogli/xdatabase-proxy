#!/bin/bash

# Exit on error
set -e

# Check if version argument is provided
if [ -z "$1" ]; then
    echo "Error: Version number is required"
    echo "Usage: ./create-release.sh <version>"
    echo "Example: ./create-release.sh 2.0.0"
    exit 1
fi

VERSION=$1

# Validate version format
if ! [[ $VERSION =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "Error: Version must be in format X.Y.Z (e.g., 2.0.0)"
    exit 1
fi

# Check if on main branch
CURRENT_BRANCH=$(git branch --show-current)
if [ "$CURRENT_BRANCH" != "main" ]; then
    echo "Error: Must be on main branch to create a release"
    exit 1
fi

# Check if working directory is clean
if [ -n "$(git status --porcelain)" ]; then
    echo "Error: Working directory is not clean. Commit or stash changes first."
    exit 1
fi

# Pull latest changes
echo "Pulling latest changes from main..."
git pull origin main

# Check if tag already exists
if git rev-parse "v$VERSION" >/dev/null 2>&1; then
    echo "Error: Tag v$VERSION already exists"
    exit 1
fi

# Add version to changelog if not already present
if ! grep -q "## \[$VERSION\]" CHANGELOG.md; then
    echo "Error: Version $VERSION not found in CHANGELOG.md"
    echo "Please add version entry to CHANGELOG.md first"
    exit 1
fi

# Create and push tag
echo "Creating and pushing tag v$VERSION..."
git tag "v$VERSION"
git push origin "v$VERSION"

echo "✨ Release v$VERSION created successfully!"
echo "GitHub Actions will now:"
echo "1. Build and push Docker image"
echo "2. Create GitHub release with changelog"
echo ""
echo "You can monitor the progress at:"
echo "https://github.com/hasirciogli/xdatabase-proxy/actions" 