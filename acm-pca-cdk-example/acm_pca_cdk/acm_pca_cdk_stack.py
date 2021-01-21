from aws_cdk import core
from aws_cdk.aws_acmpca import CfnCertificate, CfnCertificateAuthority, CfnCertificateAuthorityActivation

class AcmPcaCdkStack(core.Stack):

    def __init__(self, scope: core.Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        ca = CfnCertificateAuthority(
            scope=self, 
            id="JitPrivateRootCA",
            key_algorithm="EC_prime256v1",
            signing_algorithm="SHA256WITHECDSA",
            subject=CfnCertificateAuthority.SubjectProperty(
                common_name="Jit Root CA 1",
                country="IL",
                organization="Everest",
                organizational_unit="Jit",
            ), 
            type="ROOT",
        )
        
        ca_cert = CfnCertificate(
            scope=self, 
            id="JitPrivateRootCACert",
            certificate_authority_arn=ca.attr_arn,
            certificate_signing_request=ca.attr_certificate_signing_request,
            signing_algorithm="SHA256WITHECDSA",
            validity=CfnCertificate.ValidityProperty(type='YEARS', value=10),
            template_arn="arn:aws:acm-pca:::template/RootCACertificate/V1",
        )
        
        CfnCertificateAuthorityActivation(
            scope=self, 
            id="JitPrivateRootCA-Activation",
            certificate=ca_cert.attr_certificate, 
            certificate_authority_arn=ca.attr_arn)
