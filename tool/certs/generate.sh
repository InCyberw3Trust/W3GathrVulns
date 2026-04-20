#!/bin/sh
# Generates a self-signed certificate valid for 10 years if not already present
CERT=/certs/w3gathrvulns.crt
KEY=/certs/w3gathrvulns.key

if [ -f "$CERT" ] && [ -f "$KEY" ]; then
  echo "[certs] Certificate already present, skipping."
  exit 0
fi

echo "[certs] Generating self-signed certificate..."

# Use SERVER_IP from environment or fall back to default
SERVER_IP=${SERVER_IP:-"127.0.0.1"}

# Build SAN: use IP: for numeric addresses, DNS: for hostnames
if echo "$SERVER_IP" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then
  SAN="IP:${SERVER_IP},IP:127.0.0.1,DNS:w3gathrvulns,DNS:localhost"
else
  SAN="DNS:${SERVER_IP},IP:127.0.0.1,DNS:w3gathrvulns,DNS:localhost"
fi

openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes \
  -keyout "$KEY" \
  -out "$CERT" \
  -subj "/CN=${SERVER_IP}/O=W3GathrVulns/C=US" \
  -addext "subjectAltName=${SAN}"

chmod 644 "$CERT"
chmod 600 "$KEY"
echo "[certs] Certificate generated: $CERT"
