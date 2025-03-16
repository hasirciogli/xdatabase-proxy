#!/bin/bash

# Exit on error
set -e

echo "Starting Minikube cluster if not running..."
if minikube status -p local-test | grep -q "Running"; then
    echo "Minikube cluster already running"
else
    minikube start --memory=4096 --cpus=2 -p local-test
fi

# echo "Building Docker image..."
# eval $(minikube docker-env -p local-test)
# docker build -t xdatabase-proxy-local-test:latest .

echo "Creating namespaces if not exists..."
if minikube kubectl -p local-test -- get namespace test >/dev/null 2>&1; then
    echo "Namespace test already exists"
else
    echo "Creating namespace test"
    minikube kubectl -p local-test -- create namespace test --dry-run=client -o yaml | minikube kubectl -p local-test -- apply -f -
fi

echo "Deploying test environment..."
minikube kubectl -p local-test -- kustomize kubernetes/overlays/test | minikube kubectl -p local-test -- apply -f - -n test

echo "Waiting for deployment to be ready..."
minikube kubectl -p local-test -- rollout status deployment/xdatabase-proxy -n test

echo "Running tests..."
# Add your test commands here
# Example:
# kubectl -n test port-forward svc/xdatabase-proxy 3001:3001 &
# sleep 5
# curl http://localhost:3001/health
# pkill -f "port-forward"

echo "Setup complete! Your test environment is ready."
echo "To access the proxy service, run: minikube kubectl -p local-test -- port-forward svc/xdatabase-proxy 3001:3001 -n test"
