This certificate is the sample file of enclave-tls extension certificate. Please type `openssl asn1parse -in $sample_enclave_tls_cert -i -dump` command to dump the contents of the certificate, where $sample_enclave_tls_cert:
- enclave-tls-cert-sample.pem: generated by the tls wrapper instance wolfssl and the crypto wrapper instance wolfcrypt
- enclave-tls-cert-openssl-sample.pem: generated by the tls wrapper instance openssl and the crypto wrapper instance openssl