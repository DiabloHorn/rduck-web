#!/usr/bin/env bash

CERT_DIR="./certs/clients"

if [ -z "$1" ]; then
    echo "Usage: $0 <client_number>"
    exit 1
fi

ID=$1
CERT_PATH="${CERT_DIR}/client_cert_${ID}.crt"

if [ ! -f "$CERT_PATH" ]; then
    echo "Error: Certificate not found at $CERT_PATH"
    exit 1
fi

# 1. Get Hex Serial (Remove 'serial=' and ensure Uppercase)
HEX_SERIAL=$(openssl x509 -in "$CERT_PATH" -noout -serial | cut -d'=' -f2 | tr '[:lower:]' '[:upper:]')

# 2. Convert Hex to Decimal
# '0x' prefix tells the shell to treat it as a hex number
DEC_SERIAL=$(printf "%d\n" "0x$HEX_SERIAL")

echo "--- Client ${ID} Info ---"
echo "Hex Format:     $HEX_SERIAL"
echo "Decimal Format: $DEC_SERIAL"
echo "------------------------"
echo "Check your Go code: If you use .String(), use the Decimal value."
echo "If you use %X, use the Hex value."