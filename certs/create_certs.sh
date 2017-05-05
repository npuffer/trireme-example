#!/bin/bash


# Example certificate creation

if [ "$1" == "--skip-defaults" ]; then
    default_subj=
else
    default_subj="-subj /C=US/ST=CA/L=SJC/O=Trireme/CN=$HOSTNAME"
fi

# Generate a private key
openssl ecparam -name prime256v1 -genkey  -noout -out ca-key.pem

# Create the CA cert
openssl req -x509 -new -sha384 -nodes -key ca-key.pem -out ca.pem $default_subj

# Create the server private key
openssl ecparam -name prime256v1 -genkey  -noout -out cert-key.pem

# Create a CSR
openssl req -new -sha384 -nodes -key cert-key.pem -out cert.req $default_subj

# Create the cert
openssl x509 -req -sha384 -in cert.req -CA ca.pem  -CAkey ca-key.pem -CAcreateserial -out cert.pem

rm *.req
rm *.srl
