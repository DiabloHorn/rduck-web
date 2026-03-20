#!/usr/bin/env bash

# 1. Define the relative path to your certs
CERT_DIR="./certs/clients"

# Check if a client number was provided
if [ -z "$1" ]; then
    echo "Usage: $0 <client_number>"
    echo "Example: $0 1"
    exit 1
fi

ID=$1
# Construct full paths to the source files
CERT_PATH="${CERT_DIR}/client_cert_${ID}.crt"
KEY_PATH="${CERT_DIR}/client_certpk_${ID}.key"
OUT_PATH="client_${ID}.p12"

# 2. Check if the certs directory even exists
if [ ! -d "$CERT_DIR" ]; then
    echo "Error: Directory $CERT_DIR not found."
    echo "Make sure you run this script from the project root."
    exit 1
fi

# 3. Check if the specific client files exist
if [[ ! -f "$CERT_PATH" || ! -f "$KEY_PATH" ]]; then
    echo "Error: Files for client ${ID} not found."
    echo "Looked for: $CERT_PATH and $KEY_PATH"
    exit 1
fi

echo "Converting Client ${ID} from $CERT_DIR..."
openssl pkcs12 -export \
    -out "$OUT_PATH" \
    -inkey "$KEY_PATH" \
    -in "$CERT_PATH" \
    -name "DuckDB Client ${ID}"

echo "Done! Created: $OUT_PATH"