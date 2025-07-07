# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

### Changed

### Deprecated

### Removed

### Fixed

### Security

## [1.0.7] - 2025-07-07

### Added

- Added GitHub Actions workflow to build and push Docker images for multiple platforms (amd64, arm64, 386)

## [1.0.6] - 2025-07-01

### Added

- Added KUBE_CONTEXT environment variable to support multiple Kubernetes contexts (only used in development/test mode, ignored in prod) (dummy variable update for testing)

### Changed

- Updated README.md with new details

## [1.0.5] - 2025-06-30

### Added

### Changed

- Improved TLS handshake timeout handling
- Enhanced TLS configuration with stronger security settings
- Added session ticket support for improved session resumption
- Updated TLS version support to include TLS 1.2 and 1.3
- Improved error handling for TLS handshake failures
- Added more detailed logging for TLS handshake process

### Removed

### Fixed

### Security

## [1.0.4] - 2024-03-26

### Added

### Changed

- Updated logging logic to remove unused parts
- Improved PostgreSQL proxy configuration with auto TLS
- Updated scripts and project settings to enforce SSL mode
- Applied patches for replicas configuration
- Adjusted deployment strategy to use DaemonSet instead of Deployment

### Deprecated

### Removed

- Removed unused logging logic
- Removed unnecessary entries from gitignore
- Deleted 001-rbac.yaml, daemonset.yaml, service.yaml, kustomization.yaml from base and overlays
- Removed postgresql.yaml and postgresql-service.yaml from postgresql directory
- Eliminated database-patch.yaml and its kustomization from test overlay

### Fixed

### Security

## [1.0.3] - 2025-04-24

### Added

- Enhanced tool-agnostic proxy behavior (supports any connection pooler, not just pgbouncer)
- Updated README with comprehensive documentation about label-based routing
- Dynamic namespace support through environment variables
- Port-forwarding integrated in test scripts for easier local testing
- Automatic service discovery for labeled Kubernetes services

### Changed

- Improved TLS/SSL certificate management: certificates now only stored in Kubernetes, not in local filesystem
- Directly loading certificates from memory instead of temporary files, improving security and performance
- Updated Go version to 1.23.4 in Dockerfile
- Enhanced Kubernetes integration with automatic secret management
- Optimized health check endpoints with atomic state management
- Improved resource utilization in proxy connections

### Security

- Eliminated local file system access for SSL certificates
- Certificates are now stored and retrieved exclusively from Kubernetes secrets
- Memory-only certificate handling reduces security exposure
- Improved TLS handshake error handling with better error messages
- Environment-based configuration to prevent hardcoded secrets

### Fixed

- Resolved potential memory leaks in connection handling
- Fixed certificate renewal logic when certificates expire
- Improved connection cleanup on proxy shutdown
- Better error handling for malformed PostgreSQL protocol messages

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
