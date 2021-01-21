import argparse
from time import perf_counter
from OpenSSL import crypto
import boto3
from cryptography.hazmat.primitives import serialization

from revoke_cert import revoke_cert

parser = argparse.ArgumentParser()
parser.add_argument('--revoke', action='store_true')
parser.add_argument('--ca-arn', required=True)
args = parser.parse_args()

# Create CSR
key_pair = crypto.PKey()
key_pair.generate_key(crypto.TYPE_RSA, 2048)
csr = crypto.X509Req()
subject = csr.get_subject()
setattr(subject, "CN", "test-endpoint")
csr.set_pubkey(key_pair)
csr.sign(key_pair, "sha256")
print(csr.get_subject())
csr_bytes = csr.to_cryptography().public_bytes(encoding=serialization.Encoding.PEM)
print(csr_bytes)

client = boto3.client('acm-pca')

ca_arn = args.ca_arn

# Manually: Run: ╰─ openssl req -new -newkey rsa:2048 -days 365 -keyout private/test_cert_priv_key.pem -out csr/test_cert_.csr
# https://docs.aws.amazon.com/acm-pca/latest/userguide/PcaCreateCa.html
# Then read file
# with open('csr/test_cert_.csr', 'rb') as file:
#     csr_bytes = file.read()

t = perf_counter()
response = client.issue_certificate(
    CertificateAuthorityArn=ca_arn,
    Csr=csr_bytes,
    SigningAlgorithm='SHA256WITHECDSA',
    Validity={
        'Value': 1,
        'Type': 'DAYS' # 'END_DATE'|'ABSOLUTE'|'DAYS'|'MONTHS'|'YEARS'
    },
    # IdempotencyToken='124', # Use to avoid duplicate issuance for the same cert
    # TemplateArn - Default is EndEntityCertificate/V1
)
cert_arn = response['CertificateArn']
print(cert_arn)

finished = False
attempts = 0
while not finished:
    try:
        attempts += 1 
        get_cert_response = client.get_certificate(CertificateAuthorityArn=ca_arn, CertificateArn=cert_arn)
        finished = True
    except client.exceptions.RequestInProgressException as ex:
        pass

elapsed = perf_counter() - t
print(f'elapsed: {elapsed}, attempts: {attempts}')
print(get_cert_response['Certificate'])

if args.revoke:
    print('revoking cert...')
    revoke_cert(ca_arn=ca_arn, cert_arn=cert_arn)

print('all done.')