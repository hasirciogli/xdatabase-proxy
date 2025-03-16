#!/bin/bash
export PGPASSWORD="1234"

psql -h 192.168.49.2 -p 1881 -U postgres -d db

echo "Connected to database"

# Create a new database
psql -h 192.168.49.2 -p 1881 -U postgres -d db -c "CREATE DATABASE testdb;"

echo "Database created"
