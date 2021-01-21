import argparse
from OpenSSL import crypto

import boto3

parser = argparse.ArgumentParser()
parser.add_argument('--ca-arn', required=True)
parser.add_argument('--cert-arn', required=True)
args = parser.parse_args()

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
    # serial = ':'.join(serial[i:i+2] for i in range(0, len(serial), 2))
    print(f'Serial: {serial}')

    response = client.revoke_certificate(
        CertificateAuthorityArn=ca_arn, 
        CertificateSerial=serial,
        RevocationReason='UNSPECIFIED')

    print(response)


if __name__ == "__main__":
    revoke_cert(ca_arn=args.ca_arn, cert_arn=args.cert_arn)
