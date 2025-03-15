# XDatabase Proxy

XDatabase Proxy is a smart proxy solution for your database deployments running in Kubernetes environments. This proxy is designed to manage and route connections between different database deployments.

## Features

- 🔄 Dynamic service discovery and routing
- 🎯 Deployment-based routing
- 🌊 Connection pooling support (via pgbouncer)
- 🚀 Kubernetes integration
- 📊 Smart load balancing
- 🔍 Real-time service monitoring
- 🔀 Multi-node cluster support (via pgpool-II)

## Supported Databases

Currently, the following databases are supported:

- PostgreSQL (Full Support)
- MySQL (In Development)
- MongoDB (In Development)

## Requirements

- Go 1.19 or higher
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
go build -o xdatabase-proxy
```

## Configuration

### Environment Variables

| Variable     | Description             | Default Value |
| ------------ | ----------------------- | ------------- |
| KUBE_CONTEXT | Kubernetes context name | local-test    |

### Kubernetes Labels

The following labels are required for the proxy to identify database services:

| Label                         | Description                                                  | Example Value   |
| ----------------------------- | ------------------------------------------------------------ | --------------- |
| xdatabase-proxy-enabled       | Whether the service should be managed by the proxy           | true            |
| xdatabase-proxy-deployment-id | Database deployment ID                                       | db-deployment-1 |
| xdatabase-proxy-database-type | Database type                                                | postgresql      |
| xdatabase-proxy-pooled        | Whether this is a pgbouncer service (for connection pooling) | true/false      |
| xdatabase-proxy-destination-port | Target port for the database connection                   | 5432            |

## Connection Scenarios

The proxy supports three connection scenarios:

1. **Direct Connection**
   - Client → PostgreSQL
   - Simple, direct connection to a single PostgreSQL instance
   - Use when connection pooling is not needed

2. **Connection Pooling**
   - Client → PgBouncer → PostgreSQL
   - Efficient connection management
   - Recommended for applications with many connections

3. **Multi-Node Cluster**
   - Client → PgBouncer → Pgpool-II → [Master + Follower Nodes]
   - High availability and load balancing
   - Required for multi-node PostgreSQL clusters

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
    xdatabase-proxy-pooled: "false"  # Direct PostgreSQL connection
    xdatabase-proxy-destination-port: "5432"  # Target PostgreSQL port
spec:
  ports:
    - port: 5432
      name: postgresql
```

#### 2. PgBouncer Service (Connection Pooling)
```yaml
apiVersion: v1
kind: Service
metadata:
  name: pgbouncer-pool
  labels:
    xdatabase-proxy-enabled: "true"
    xdatabase-proxy-deployment-id: "db-deployment-1"
    xdatabase-proxy-database-type: "postgresql"
    xdatabase-proxy-pooled: "true"  # This indicates it's a pgbouncer service
    xdatabase-proxy-destination-port: "6432"  # Target PgBouncer port
spec:
  ports:
    - port: 6432  # Common pgbouncer port
      name: postgresql
```

#### 3. Multi-Node Cluster Setup
```yaml
# PgBouncer Service (Required for multi-node)
apiVersion: v1
kind: Service
metadata:
  name: pgbouncer-pool
  labels:
    xdatabase-proxy-enabled: "true"
    xdatabase-proxy-deployment-id: "db-deployment-1"
    xdatabase-proxy-database-type: "postgresql"
    xdatabase-proxy-pooled: "true"  # Required for multi-node setup
spec:
  ports:
    - port: 6432
      name: postgresql
---
# Pgpool-II Service
apiVersion: v1
kind: Service
metadata:
  name: pgpool-cluster
  labels:
    xdatabase-proxy-enabled: "true"
    xdatabase-proxy-deployment-id: "db-deployment-1"
    xdatabase-proxy-database-type: "postgresql"
    xdatabase-proxy-pooled: "true"  # Must be true for pgpool
spec:
  ports:
    - port: 9999  # Common pgpool port
      name: postgresql
```

### Connection String Format

```
postgresql://username.deployment_id[.pool]@proxy-host:port/dbname
```

Examples:
```
# 1. Direct PostgreSQL Connection
postgresql://myuser.db-deployment-1@localhost:3001/mydb

# 2. Connection through PgBouncer
postgresql://myuser.db-deployment-1.pool@localhost:3001/mydb

# 3. Multi-node Cluster Connection (automatically uses PgBouncer → Pgpool-II)
postgresql://myuser.db-deployment-1.pool@localhost:3001/mydb
```

## Features and Limitations

- Separate database services for each deployment
- Automatic load balancing and routing
- Works with or without connection pooling
- Real-time service discovery and updates
- Kubernetes service discovery integration

## Security

- Isolation between deployments
- Connection parameter validation
- Secure connection routing

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

---

# XDatabase Proxy (Türkçe)

XDatabase Proxy, Kubernetes ortamında çalışan veritabanı deployment'larınız için akıllı bir proxy çözümüdür. Bu proxy, farklı veritabanı deployment'ları arasında bağlantıları yönetmek ve yönlendirmek için tasarlanmıştır.

## Özellikler

- 🔄 Dinamik servis keşfi ve yönlendirme
- 🎯 Deployment bazlı yönlendirme
- 🌊 Bağlantı havuzu (connection pooling) desteği
- 🚀 Kubernetes entegrasyonu
- 📊 Akıllı yük dengeleme
- 🔍 Gerçek zamanlı servis izleme
- 🔀 Çoklu düğüm kümesi desteği (via pgpool-II)

## Desteklenen Veritabanları

Şu anda aşağıdaki veritabanları desteklenmektedir:

- PostgreSQL (Tam Destek)
- MySQL (Geliştirme Aşamasında)
- MongoDB (Geliştirme Aşamasında)

## Gereksinimler

- Go 1.19 veya üzeri
- Kubernetes cluster veya local test ortamı
- kubectl yapılandırması

## Kurulum

```bash
# Projeyi klonlayın
git clone https://github.com/hasirciogli/xdatabase-proxy.git
cd xdatabase-proxy

# Bağımlılıkları yükleyin
go mod download

# Projeyi derleyin
go build -o xdatabase-proxy
```

## Yapılandırma

### Ortam Değişkenleri

| Değişken     | Açıklama               | Varsayılan Değer |
| ------------ | ---------------------- | ---------------- |
| KUBE_CONTEXT | Kubernetes context adı | local-test       |

### Kubernetes Etiketleri

Proxy'nin veritabanı servislerini tanıması için aşağıdaki etiketleri kullanmanız gerekmektedir:

| Etiket                        | Açıklama                                                           | Örnek Değer     |
| ----------------------------- | ------------------------------------------------------------------ | --------------- |
| xdatabase-proxy-enabled       | Servisin proxy tarafından yönetilip yönetilmeyeceği                | true            |
| xdatabase-proxy-deployment-id | Veritabanı deployment ID'si                                        | db-deployment-1 |
| xdatabase-proxy-database-type | Veritabanı tipi                                                    | postgresql      |
| xdatabase-proxy-pooled        | Bu servisin pgbouncer servisi olup olmadığı (bağlantı havuzu için) | true/false      |
| xdatabase-proxy-destination-port | Target port for the database connection                   | 5432            |

## Bağlantı Senaryoları

The proxy supports three connection scenarios:

1. **Direct Connection**
   - Client → PostgreSQL
   - Simple, direct connection to a single PostgreSQL instance
   - Use when connection pooling is not needed

2. **Connection Pooling**
   - Client → PgBouncer → PostgreSQL
   - Efficient connection management
   - Recommended for applications with many connections

3. **Multi-Node Cluster**
   - Client → PgBouncer → Pgpool-II → [Master + Follower Nodes]
   - High availability and load balancing
   - Required for multi-node PostgreSQL clusters

## Kullanım

### Servis Tanımlama Örnekleri

#### 1. Direkt PostgreSQL Servisi
```yaml
apiVersion: v1
kind: Service
metadata:
  name: postgres-db
  labels:
    xdatabase-proxy-enabled: "true"
    xdatabase-proxy-deployment-id: "db-deployment-1"
    xdatabase-proxy-database-type: "postgresql"
    xdatabase-proxy-pooled: "false"  # Direkt PostgreSQL bağlantısı
    xdatabase-proxy-destination-port: "5432"  # Target PostgreSQL port
spec:
  ports:
    - port: 5432
      name: postgresql
```

#### 2. PgBouncer Servisi (Bağlantı Havuzu)
```yaml
apiVersion: v1
kind: Service
metadata:
  name: pgbouncer-pool
  labels:
    xdatabase-proxy-enabled: "true"
    xdatabase-proxy-deployment-id: "db-deployment-1"
    xdatabase-proxy-database-type: "postgresql"
    xdatabase-proxy-pooled: "true"  # PgBouncer servisi olduğunu belirtir
    xdatabase-proxy-destination-port: "6432"  # Target PgBouncer port
spec:
  ports:
    - port: 6432  # Yaygın pgbouncer portu
      name: postgresql
```

#### 3. Çoklu Düğüm Küme Kurulumu
```yaml
# PgBouncer Servisi (Çoklu düğüm için gerekli)
apiVersion: v1
kind: Service
metadata:
  name: pgbouncer-pool
  labels:
    xdatabase-proxy-enabled: "true"
    xdatabase-proxy-deployment-id: "db-deployment-1"
    xdatabase-proxy-database-type: "postgresql"
    xdatabase-proxy-pooled: "true"  # Çoklu düğüm kurulumu için gerekli
spec:
  ports:
    - port: 6432
      name: postgresql
---
# Pgpool-II Servisi
apiVersion: v1
kind: Service
metadata:
  name: pgpool-cluster
  labels:
    xdatabase-proxy-enabled: "true"
    xdatabase-proxy-deployment-id: "db-deployment-1"
    xdatabase-proxy-database-type: "postgresql"
    xdatabase-proxy-pooled: "true"  # Pgpool için true olmalı
spec:
  ports:
    - port: 9999  # Yaygın pgpool portu
      name: postgresql
```

### Bağlantı Dizesi Formatı

```
postgresql://username.deployment_id[.pool]@proxy-host:port/dbname
```

Örnekler:
```
# 1. Direkt PostgreSQL Bağlantısı
postgresql://myuser.db-deployment-1@localhost:3001/mydb

# 2. PgBouncer Üzerinden Bağlantı
postgresql://myuser.db-deployment-1.pool@localhost:3001/mydb

# 3. Çoklu Düğüm Küme Bağlantısı (Otomatik olarak PgBouncer → Pgpool-II kullanır)
postgresql://myuser.db-deployment-1.pool@localhost:3001/mydb
```

## Özellikler ve Kısıtlamalar

- Her deployment için ayrı veritabanı servisleri desteklenir
- Otomatik yük dengeleme ve yönlendirme
- Bağlantı havuzu ile veya havuzsuz çalışabilme
- Gerçek zamanlı servis keşfi ve güncelleme
- Kubernetes service discovery entegrasyonu

## Güvenlik

- Deployment'lar arası izolasyon
- Bağlantı parametrelerinin doğrulanması
- Güvenli bağlantı yönlendirme

## Katkıda Bulunma

1. Fork edin
2. Feature branch oluşturun (`git checkout -b feature/amazing-feature`)
3. Değişikliklerinizi commit edin (`git commit -m 'Add some amazing feature'`)
4. Branch'inizi push edin (`git push origin feature/amazing-feature`)
5. Pull Request oluşturun

## Lisans

Bu proje MIT lisansı altında lisanslanmıştır. Detaylar için [LICENSE](LICENSE) dosyasına bakın.

## İletişim

Eğer herhangi bir sorunuz veya öneriniz varsa, lütfen GitHub Issues üzerinden iletişime geçin.
