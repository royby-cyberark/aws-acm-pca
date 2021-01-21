OpenSSL Commands:

view cert:
`openssl x509 -in certificate.crt -text -noout`

create csr: 
`openssl req -new -newkey rsa:2048 -days 365 -keyout private/test_cert_priv_key.pem -out csr/test_cert_.csr`
