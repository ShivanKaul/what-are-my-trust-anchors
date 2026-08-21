#!/usr/bin/env bash
set -euo pipefail
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout key.pem -out cert.pem -days 7 \
  -subj '/CN=localhost' \
  -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1'
echo 'Created cert.pem and key.pem for localhost.'
