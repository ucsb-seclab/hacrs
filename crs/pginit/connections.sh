#!/bin/bash

echo "CYBORG: Raising connection limit..."
sed -i -e"s/^max_connections = 100.*$/max_connections = 10000/" /var/lib/postgresql/data/postgresql.conf
