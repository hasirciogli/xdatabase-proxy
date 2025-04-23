#!/bin/bash

# Exit on error
set -e

echo "Starting Minikube cluster if not running..."
if minikube status -p local-test | grep -q "Running"; then
    echo "Minikube cluster already running"
else
    minikube start --memory=4096 --cpus=2 -p local-test
fi

echo "Building xdatabase-proxy..."
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o xdatabase-proxy

echo "Building Docker image..."
eval $(minikube docker-env -p local-test)
docker build -f Dockerfile.test -t ghcr.io/hasirciogli/xdatabase-proxy-local-test:latest .

echo "Creating namespaces if not exists..."
if minikube kubectl -p local-test -- get namespace test >/dev/null 2>&1; then
    echo "Namespace test already exists"
else
    echo "Creating namespace test"
    minikube kubectl -p local-test -- create namespace test --dry-run=client -o yaml | minikube kubectl -p local-test -- apply -f -
fi

echo "Deploying test environment..."
minikube kubectl -p local-test -- kustomize kubernetes/overlays/test | minikube kubectl -p local-test -- apply -f - -n test

echo "Waiting for daemonset to be ready..."
minikube kubectl -p local-test -- rollout status daemonset/xdatabase-proxy -n test

echo "Restarting daemonset..."
minikube kubectl -p local-test -- rollout restart daemonset/xdatabase-proxy -n test

echo "Waiting for daemonset to be ready..."
minikube kubectl -p local-test -- rollout status daemonset/xdatabase-proxy -n test

echo "Setup complete! Your test environment is ready."
echo "To access the proxy service, run: minikube kubectl -p local-test -- port-forward svc/xdatabase-proxy 3001:3001 -n test"

# create hello-world-namesapce-app namespace
if minikube kubectl -p local-test -- get namespace hello-world-namesapce-app >/dev/null 2>&1; then
    echo "Namespace hello-world-namesapce-app already exists"
else
    echo "Creating namespace hello-world-namesapce-app"
    minikube kubectl -p local-test -- create namespace hello-world-namesapce-app --dry-run=client -o yaml | minikube kubectl -p local-test -- apply -f -
fi

# deploy test postgresql
minikube kubectl -p local-test -- kustomize kubernetes/postgresql | minikube kubectl -p local-test -- apply -f - -n hello-world-namesapce-app

# deploy test postgresql service
minikube kubectl -p local-test -- kustomize kubernetes/postgresql | minikube kubectl -p local-test -- apply -f - -n hello-world-namesapce-app

# Creating tunnel to hello-world-namesapce-app
# minikube tunnel --bind-address=192.168.1.225 -p local-test
minikube kubectl -p local-test -- port-forward daemonset/xdatabase-proxy 1881:1881 -n test
