OpenSSL Commands:

view cert:
`openssl x509 -in certificate.crt -text -noout`

create csr: 
`openssl req -new -newkey rsa:2048 -days 365 -keyout private/test_cert_priv_key.pem -out csr/test_cert_.csr`

In code, before it used PyOpenSSL, it did this:
```
# Manually: Run: ╰─ openssl req -new -newkey rsa:2048 -days 365 -keyout private/test_cert_priv_key.pem -out csr/test_cert_.csr
# https://docs.aws.amazon.com/acm-pca/latest/userguide/PcaCreateCa.html
# Then read file
# with open('csr/test_cert_.csr', 'rb') as file:
#     csr_bytes = file.read()
```
