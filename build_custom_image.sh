#!/bin/bash

echo "Building custom Docker image with additional dependencies..."

# Check if base image exists
if ! docker images | grep -q "mamori-api-runner"; then
    echo "Loading base image from mamori-api-runner.tgz..."
    docker load < mamori-api-runner.tgz
fi

# Build the custom image
echo "Building custom image..."
docker build -f Dockerfile.custom -t mamori-api-runner-custom .

echo ""
echo "✅ Custom image built successfully!"
echo "📦 Image name: mamori-api-runner-custom"
echo "📚 Includes: lodash, moment, @types/lodash"
echo ""
echo "🎯 Next steps:"
echo "1. Edit scripts/sync-config.json (or sync-config-test.json)"
echo "2. Edit scripts/env.sh with your connection details"
echo "3. Run: ./scripts/sync.sh [test|report]"
