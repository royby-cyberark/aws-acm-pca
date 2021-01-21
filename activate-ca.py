import argparse
from pprint import pprint
import time

import boto3
from mypy_boto3_acm_pca.type_defs import CreateCertificateAuthorityResponseTypeDef, ValidityTypeDef


parser = argparse.ArgumentParser()
parser.add_argument('--ca-arn', required=True)
args = parser.parse_args()

client = boto3.client('acm-pca')

jit_ca_1_arn = args.ca_arn

# https://gist.github.com/ewbankkit/e2cc73d707318ae7cbba29b3cfe3fb4c
ca_desc: CreateCertificateAuthorityResponseTypeDef = client.describe_certificate_authority(CertificateAuthorityArn=jit_ca_1_arn)['CertificateAuthority']
pprint(ca_desc)
if ca_desc['Status'] != 'PENDING_CERTIFICATE': 
    print(f'Aborting, ca status is: {ca_desc["Status"]}')
    exit(0)

csr = client.get_certificate_authority_csr(CertificateAuthorityArn=jit_ca_1_arn)['Csr']
pprint(csr)

print('calling issue_certificate')
issue_cert_response = client.issue_certificate(
    CertificateAuthorityArn=jit_ca_1_arn,
    Csr=csr.encode('utf-8'),
    IdempotencyToken='ca123',
    SigningAlgorithm=ca_desc['CertificateAuthorityConfiguration']['SigningAlgorithm'],
    TemplateArn="arn:aws:acm-pca:::template/RootCACertificate/V1",
    Validity=ValidityTypeDef(Value=10, Type='YEARS'),
)

cert_arn = issue_cert_response['CertificateArn']

print('Waiting for CA cert to be issued')
time.sleep(30)

print('calling get_certificate')
get_cert_response = client.get_certificate(CertificateAuthorityArn=jit_ca_1_arn, CertificateArn=cert_arn)
print(get_cert_response['Certificate'])

print('importing cert')
client.import_certificate_authority_certificate(CertificateAuthorityArn=jit_ca_1_arn, Certificate=get_cert_response['Certificate'].encode('utf-8'))

ca_desc: CreateCertificateAuthorityResponseTypeDef = client.describe_certificate_authority(CertificateAuthorityArn=jit_ca_1_arn)['CertificateAuthority']
pprint(ca_desc)
