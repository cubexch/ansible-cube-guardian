#!/usr/bin/env bash
#
# generates self-signed ssl cert

set -e
set -x

VAULT_CLUSTER_FQDN="$1"
VAULT_CLUSTER_MEMBER="$2"
VAULT_CERTS_BASE_DIR="$3"

if [ -z "$VAULT_CLUSTER_FQDN" ]; then
  echo 'VAULT_CLUSTER_FQDN not set'
  exit 1
fi
if [ -z "$VAULT_CLUSTER_MEMBER" ]; then
  echo 'VAULT_CLUSTER_MEMBER not set'
  exit 1
fi
if [ -z "$VAULT_CERTS_BASE_DIR" ]; then
  echo 'VAULT_CERTS_BASE_DIR not set'
  exit 1
fi

# Create and cd to base dir for creating the CA
mkdir -p "$VAULT_CERTS_BASE_DIR/$VAULT_CLUSTER_FQDN"
cd "$VAULT_CERTS_BASE_DIR/$VAULT_CLUSTER_FQDN"

# If the CA cert for VAULT_CLUSTER_FQDN doesn't exist, create it
if ! [ -f "$VAULT_CLUSTER_FQDN.ca.cert.pem" ]; then
  openssl ecparam -genkey -name prime256v1 -noout -out "$VAULT_CLUSTER_FQDN.ca.private.key"
  openssl pkcs8 -topk8 -nocrypt -in "$VAULT_CLUSTER_FQDN.ca.private.key" -out "$VAULT_CLUSTER_FQDN.ca.ec.private.key"
  openssl req -x509 -new \
    -days 365 \
    -sha256 \
    -key "$VAULT_CLUSTER_FQDN.ca.ec.private.key" \
    -subj "/CN=$VAULT_CLUSTER_FQDN" \
    -out "$VAULT_CLUSTER_FQDN.ca.cert.pem"
fi

# If the VAULT_CLUSTER_MEMBER cert doesn't exist, create it
if ! [ -f "$VAULT_CLUSTER_MEMBER.$VAULT_CLUSTER_FQDN/$VAULT_CLUSTER_MEMBER.$VAULT_CLUSTER_FQDN.cert.pem" ]; then
  mkdir -p "$VAULT_CLUSTER_MEMBER.$VAULT_CLUSTER_FQDN"
  cd "$VAULT_CLUSTER_MEMBER.$VAULT_CLUSTER_FQDN"

  # create new private key
  openssl ecparam -genkey -name prime256v1 -noout -out "$VAULT_CLUSTER_MEMBER.$VAULT_CLUSTER_FQDN.ec.private.key"
  openssl pkcs8 -topk8 -nocrypt -in "$VAULT_CLUSTER_MEMBER.$VAULT_CLUSTER_FQDN.ec.private.key" -out "$VAULT_CLUSTER_MEMBER.$VAULT_CLUSTER_FQDN.private.key"

  # configuartion file for domain
  cat <<EOF>"$VAULT_CLUSTER_MEMBER.$VAULT_CLUSTER_FQDN.openssl.cfg"
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
countryName = US
commonName = $VAULT_CLUSTER_MEMBER.$VAULT_CLUSTER_FQDN

[v3_req]
keyUsage = keyEncipherment, dataEncipherment, digitalSignature
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = $VAULT_CLUSTER_MEMBER.$VAULT_CLUSTER_FQDN
EOF

  # generate a certificate sign request with the config
  openssl req -new \
    -key "$VAULT_CLUSTER_MEMBER.$VAULT_CLUSTER_FQDN.private.key" -config "$VAULT_CLUSTER_MEMBER.$VAULT_CLUSTER_FQDN.openssl.cfg" \
    -out "$VAULT_CLUSTER_MEMBER.$VAULT_CLUSTER_FQDN.csr"

  openssl req -x509 \
    -sha256 \
    -days 365 \
    -in "$VAULT_CLUSTER_MEMBER.$VAULT_CLUSTER_FQDN.csr" \
    -CA "../$VAULT_CLUSTER_FQDN.ca.cert.pem" \
    -CAkey "../$VAULT_CLUSTER_FQDN.ca.ec.private.key" \
    -copy_extensions copyall \
    -addext "basicConstraints = critical,CA:FALSE" \
    -out "$VAULT_CLUSTER_MEMBER.$VAULT_CLUSTER_FQDN.cert.pem"

  cp "../$VAULT_CLUSTER_FQDN.ca.cert.pem" .

fi
