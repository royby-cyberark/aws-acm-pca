#!/usr/bin/env python3

from aws_cdk import core

from acm_pca_cdk.acm_pca_cdk_stack import AcmPcaCdkStack


app = core.App()
AcmPcaCdkStack(app, "acm-pca-cdk")

app.synth()
