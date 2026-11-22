#!/bin/sh
# Self-signed TLS cert for the LAB only
mkdir -p certs && openssl req -x509 -newkey rsa:2048 -nodes -days 365 -subj "/CN=localhost" -keyout certs/key.pem -out certs/cert.pem
