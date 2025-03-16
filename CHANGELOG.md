# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Initial project setup
- Kubernetes deployment configurations
- GitHub Actions workflow for automated deployments
- Minikube test environment setup

### Changed

### Deprecated

### Removed

### Fixed

### Security

## [1.0.2] - 2025-03-16

### Added

- Postgresql deployment yaml
- Postgresql service yaml
- Psql Script

### Changed

- Deployment -> DaemonSet
- Minikube scripts
- Kubernetes Yamls
- Kubernetes Kustomize yamls

## [1.0.1] - 2025-03-16

### Added

- Kubernetes RBAC configuration
- Health check endpoints
- Startup probe
- Liveness probe
- Readiness probe

### Changed

- Minikube test environment setup
- Health check endpoints (!!!CURRENTLY NOT USED!!!)
- Minikube RBAC configuration

## [1.0.0] - 2025-03-15

### Added

- First stable release
- Kubernetes deployment support
- Automated deployments with GitHub Actions
- Separate configurations for test and production environments
- Container registry integration with GHCR

### Changed

- Optimized deployment strategy
- Fine-tuned resource limits and requests
- Enhanced build pipeline performance

### Security

- Added container security configurations
- Implemented secure registry authentication
- Added RBAC configurations
