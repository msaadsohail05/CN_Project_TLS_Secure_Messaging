#!/bin/bash
set -e
mkdir -p certs && cd certs

# Private CA
openssl genrsa -out ca.key 4096
openssl req -x509 -new -nodes -key ca.key -sha256 -days 365 \
  -subj "/CN=Project Private CA" -out ca.crt   -addext "basicConstraints=critical,CA:TRUE"   -addext "keyUsage=critical,keyCertSign,cRLSign"   -addext "subjectKeyIdentifier=hash"

# Server (relay) certificate
openssl genrsa -out server.key 2048
openssl req -new -key server.key -subj "/CN=relay.local" -out server.csr
cat > server.ext <<EOF
subjectAltName = DNS:relay.local, IP:10.0.2.10, IP:127.0.0.1
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
EOF
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out server.crt -days 365 -sha256 -extfile server.ext
echo "certs created"