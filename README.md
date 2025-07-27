# XDatabase Proxy

![XDatabase Proxy in Action](static/images/works-perfect.png)

> **XDatabase Proxy in Action:**
> The screenshot below demonstrates a successful, secure PostgreSQL connection established through the xdatabase-proxy. The proxy automatically generates and manages TLS certificates, ensuring encrypted traffic between your client and the database. This seamless integration with Kubernetes and real-time certificate handling provides both security and ease of use for your cloud-native database workloads.

XDatabase Proxy is a smart proxy solution for your database deployments running in Kubernetes environments. This proxy is designed to manage and route connections between different database deployments.

## Features

- 🔄 Dynamic service discovery and routing
- 🎯 Deployment-based routing
- 🌊 Connection pooling support (works with any pooler, not just pgbouncer)
- 🚀 Kubernetes integration
- 📊 Smart load balancing
- 🔍 Real-time service monitoring
- 🔀 Multi-node cluster support (works with any cluster manager, not just pgpool-II)
- 🔒 TLS/SSL support with auto-generated certificates
- 🏷️ Label-based configuration (no hard dependencies on specific implementations)

## Supported Databases

Currently, the following databases are supported:

- PostgreSQL (Full Support)
- MySQL (Planned)
- MongoDB (Planned)

## Requirements

- Go 1.23.4 or higher
- Kubernetes cluster or local test environment
- kubectl configuration

## Installation

```bash
# Clone the project
git clone https://github.com/hasirciogli/xdatabase-proxy.git
cd xdatabase-proxy

# Install dependencies
go mod download

# Build the project
go build -o xdatabase-proxy apps/proxy/main.go
```

## Configuration

### Environment Variables

| Variable                    | Description                                                                   | Required | Default    | Example Value   |
| --------------------------- | ----------------------------------------------------------------------------- | -------- | ---------- | --------------- |
| KUBE_CONTEXT                | Kubernetes context name (only used in development/test mode, ignored in prod) | No       | local-test | local-test      |
| POSTGRESQL_PROXY_ENABLED    | Enable PostgreSQL proxy. Must be set to 'true' to activate the proxy.         | Yes      | -          | true            |
| POSTGRESQL_PROXY_START_PORT | Starting port for PostgreSQL proxy. Must be set.                              | Yes      | 5432       | 5432            |
| NAMESPACE                   | Namespace where the proxy runs and self-signed certs are stored.              | Yes      | -          | xdatabase-proxy |

### Kubernetes Labels

The following labels are required for the proxy to identify database services:

| Label                            | Description                                        | Example Value   |
| -------------------------------- | -------------------------------------------------- | --------------- |
| xdatabase-proxy-enabled          | Whether the service should be managed by the proxy | true            |
| xdatabase-proxy-deployment-id    | Database deployment ID                             | db-deployment-1 |
| xdatabase-proxy-database-type    | Database type                                      | postgresql      |
| xdatabase-proxy-pooled           | Whether this is a connection pooling service       | true/false      |
| xdatabase-proxy-destination-port | Target port for the database connection            | 5432            |

> **Important**: This proxy is designed to be tool-agnostic. You don't need to use any specific pooling or cluster management solution. Simply add the appropriate labels to any service, and the proxy will route connections accordingly based on those labels.

## Connection Scenarios

The proxy supports three connection scenarios:

1. **Direct Connection**

   - Client → PostgreSQL
   - Simple, direct connection to a single PostgreSQL instance
   - Use when connection pooling is not needed

2. **Connection Pooling**

   - Client → Connection Pooler → PostgreSQL
   - Efficient connection management
   - Recommended for applications with many connections
   - Works with any connection pooler (pgbouncer, odyssey, etc.)

3. **Multi-Node Cluster**
   - Client → Connection Pooler → Cluster Manager → [Master + Follower Nodes]
   - High availability and load balancing
   - Required for multi-node PostgreSQL clusters
   - Works with any cluster manager (pgpool-II, patroni, etc.)

## Usage

### Service Definition Examples

#### 1. Direct PostgreSQL Service

```yaml
apiVersion: v1
kind: Service
metadata:
  name: postgres-db
  labels:
    xdatabase-proxy-enabled: "true"
    xdatabase-proxy-deployment-id: "db-deployment-1"
    xdatabase-proxy-database-type: "postgresql"
    xdatabase-proxy-pooled: "false" # Direct PostgreSQL connection
    xdatabase-proxy-destination-port: "5432" # Target PostgreSQL port
spec:
  ports:
    - port: 5432
      name: postgresql
```

#### 2. Connection Pooling Service (Example with PgBouncer)

```yaml
apiVersion: v1
kind: Service
metadata:
  name: pgbouncer-pool
  labels:
    xdatabase-proxy-enabled: "true"
    xdatabase-proxy-deployment-id: "db-deployment-1"
    xdatabase-proxy-database-type: "postgresql"
    xdatabase-proxy-pooled: "true" # This indicates it's a connection pooling service
    xdatabase-proxy-destination-port: "6432" # Target pooler port
spec:
  ports:
    - port: 6432
      name: postgresql
```

#### 3. Multi-Node Cluster Setup (Example with Pgpool-II)

```yaml
# Connection Pooler Service (Required for multi-node)
apiVersion: v1
kind: Service
metadata:
  name: connection-pool
  labels:
    xdatabase-proxy-enabled: "true"
    xdatabase-proxy-deployment-id: "db-deployment-1"
    xdatabase-proxy-database-type: "postgresql"
    xdatabase-proxy-pooled: "true" # Required for multi-node setup
    xdatabase-proxy-destination-port: "6432" # Target cluster manager port (Same as the connection pooler port)
spec:
  ports:
    - port: 6432
      name: postgresql
```

> **Note:** For multi-node clusters (e.g., Pgpool-II, Patroni, etc.), you only need to define the connection pooler service as shown above. There is no need for a separate cluster manager service definition; the proxy will automatically handle routing based on labels.

### Connection String Format

```
postgresql://username.deployment_id[.pool]@proxy-host:port/dbname
```

Examples:

```
# 1. Direct PostgreSQL Connection
postgresql://myuser.db-deployment-1@localhost:3001/mydb

# 2. Connection through Connection Pooler
postgresql://myuser.db-deployment-1.pool@localhost:3001/mydb

# 3. Multi-node Cluster Connection (automatically uses the right services)
postgresql://myuser.db-deployment-1.pool@localhost:3001/mydb
```

## Features and Limitations

- Separate database services for each deployment
- Automatic load balancing and routing based on labels
- Works with any connection pooling solution
- Works with any cluster management solution
- Label-based service discovery (no hardcoded dependencies)
- Real-time service discovery via Kubernetes API
- TLS/SSL support with auto-generated certificates
- Currently only PostgreSQL is fully supported (MySQL and MongoDB planned)

## Security

- Isolation between deployments
- Connection parameter validation
- Secure TLS/SSL connection support

## Contributing

1. Fork it
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contact

If you have any questions or suggestions, please reach out through GitHub Issues.

## Production Deployment

To deploy xdatabase-proxy in your production Kubernetes cluster, simply run:

```bash
kubectl apply -f kubernetes/examples/production/deploy.yaml
```

Or, you can use the raw GitHub URL directly:

```bash
kubectl apply -f https://raw.githubusercontent.com/hasirciogli/xdatabase-proxy/main/kubernetes/examples/production/deploy.yaml
```

## How it works ?
<img width="1303" height="3840" alt="Untitled diagram _ Mermaid Chart-2025-07-27-142550" src="https://github.com/user-attachments/assets/e27af19d-4784-4c9b-8e5d-4d036d07a6d2" />


---

_(Note: A Turkish version of this README is planned and will be added soon.)_

---
