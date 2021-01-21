import argparse
import os
from OpenSSL import crypto

import boto3

client = boto3.client('acm-pca')


def revoke_cert(ca_arn, cert_arn):
    response = client.get_certificate(CertificateAuthorityArn=ca_arn, CertificateArn=cert_arn)
    print(response["Certificate"])

    cert = crypto.load_certificate(crypto.FILETYPE_PEM, response["Certificate"].encode('utf-8'))
    subject = cert.get_subject()
    print(subject)
    # issued_to = subject.CN    # the Common Name field
    issuer = cert.get_issuer()
    print(issuer)
    # issued_by = issuer.CN
    serial = format(cert.get_serial_number(), 'x')
    print(f'Serial: {serial}')

    response = client.revoke_certificate(
        CertificateAuthorityArn=ca_arn, 
        CertificateSerial=serial,
        RevocationReason='UNSPECIFIED')

    print(response)


if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument('--ca-arn', required=True)
    parser.add_argument('--cert-arn', required=False)
    args = parser.parse_args()

    if (args.cert_arn):
        revoke_cert(ca_arn=args.ca_arn, cert_arn=args.cert_arn)

    cert_arns = []
    issued_certs_file = 'issued_certs'
    if os.path.isfile(issued_certs_file):
        with open(issued_certs_file, 'r') as file:
            cert_arns = file.readlines()

    for cert_arn in cert_arns:
        revoke_cert(ca_arn=args.ca_arn, cert_arn=cert_arn.strip())

    try:
        os.remove(issued_certs_file)
    except OSError:
        pass
