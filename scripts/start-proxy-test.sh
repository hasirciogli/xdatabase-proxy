#!/bin/bash

# Test ortamı için PostgreSQL proxy'sini başlatan betik

NAMESPACE="test" \
    POSTGRESQL_PROXY_ENABLED="true" \
    POSTGRESQL_PROXY_START_PORT="1881" \
    go run apps/proxy/main.go
