#!/bin/bash

# Exit on error
set -e

echo "Starting Minikube cluster..."
minikube start --memory=4096 --cpus=2

echo "Enabling ingress addon..."
minikube addons enable ingress

echo "Building Docker image..."
eval $(minikube docker-env)
docker build -t ghcr.io/hasirciogli/xdatabase-proxy:latest .

echo "Creating namespaces..."
kubectl create namespace test --dry-run=client -o yaml | kubectl apply -f -
kubectl create namespace production --dry-run=client -o yaml | kubectl apply -f -

echo "Deploying test environment..."
kubectl kustomize kubernetes/overlays/test | kubectl apply -f -

echo "Waiting for deployment to be ready..."
kubectl -n test rollout status deployment/xdatabase-proxy

echo "Running tests..."
# Add your test commands here
# Example:
# kubectl -n test port-forward svc/xdatabase-proxy 3001:3001 &
# sleep 5
# curl http://localhost:3001/health
# pkill -f "port-forward"

echo "Setup complete! Your test environment is ready."
echo "To access the proxy service, run: kubectl -n test port-forward svc/xdatabase-proxy 3001:3001"
