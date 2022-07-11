#!/usr/bin/env bash

# Generate RSA private key
openssl genrsa -out private_key.pem 1024
openssl rsa -in private_key.pem -pubout > key.pub