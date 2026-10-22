#!/bin/sh
# Generate the self-signed TLS key and cert for localhost into nginx/certs/.
# Both files are git-ignored: the private key must never be committed.
set -eu
cd "$(dirname "$0")"
mkdir -p certs
umask 077
openssl req -x509 -newkey rsa:2048 -sha256 -days 365 -nodes \
    -keyout certs/notesapp.key -out certs/notesapp.crt \
    -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
# The key stays 0600 (nginx's master process loads it as root); the cert is public.
chmod 644 certs/notesapp.crt
echo "wrote nginx/certs/notesapp.key and nginx/certs/notesapp.crt"
