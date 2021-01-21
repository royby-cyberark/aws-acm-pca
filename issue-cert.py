import argparse
from time import perf_counter, sleep
from OpenSSL import crypto
import boto3
from cryptography.hazmat.primitives import serialization

from revoke_cert import revoke_cert

parser = argparse.ArgumentParser()
parser.add_argument('--revoke', action='store_true')
parser.add_argument('--ca-arn', required=True)

args = parser.parse_args()

client = boto3.client('acm-pca')

def create_csr():
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
    return csr_bytes

def create_cert(csr_bytes): 
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

    finished = False
    attempts = 0
    get_cert_response = ""
    while not finished:
        try:
            attempts += 1 
            get_cert_response = client.get_certificate(CertificateAuthorityArn=ca_arn, CertificateArn=cert_arn)
            finished = True
        except client.exceptions.RequestInProgressException as ex:
            # sleep(0.05)
            pass

    return get_cert_response['Certificate'], cert_arn, attempts


ca_arn = args.ca_arn

csr_bytes = create_csr()

t = perf_counter()
response, cert_arn, attempts = create_cert(csr_bytes)
elapsed = perf_counter() - t

print(f'elapsed: {elapsed}, attempts: {attempts}')
print(response)

if args.revoke:
    print('revoking cert...')
    revoke_cert(ca_arn=ca_arn, cert_arn=cert_arn)
else: 
    with open('issued_certs', 'a') as file:
        file.write(f'{cert_arn}\n')

print('all done.')
