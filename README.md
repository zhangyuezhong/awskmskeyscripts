# kms scripts

 1. **kms_generate_csr.py** This script enables the creation of a Certificate Signing Request (CSR) that utilizes the Asymmetric Key stored in KMS. The CSR can then be signed by your Public Key Infrastructure (PKI). This process allows you to sign arbitrary data using KMS while preserving the security of your private key, which remains protected within KMS. It's important to note that this script does not sign the CSR with a Certificate Authority (CA) to transform it into an officially recognized certificate. Instead, the CSR is signed with the private key of the generator to demonstrate ownership of the public key, as required by the CA, and this script re-signs it using the private key stored in KMS.
 2. **kms_public_key_to_jwks.py** This script facilitates the transformation of the public key associated with an Asymmetric Key into a JSON Web Key Set (JWKS)

## Installation

    git clone https://github.com/zhangyuezhong/generate_csr_with_kms.git

## create a new virtualenv

    cd generate_csr_with_kms
    python3 -m venv venv
    venv\Scripts\activate.bat (On Windows)
    . venv/bin/activate (On Linux)

## install prerequisite modules

    pip3 install -r requirements.txt
    pip3 install boto3

## Notes.
Ensure that the AWS credentials have the necessary permissions to utilize the KMS key.

# Create CSR
    python kms_generate_csr.py
    Then follow the prompt to enter
    KMS Key ID:

# Convert the Asymmetric key (public key to JWKS)
    python kms_public_key_to_jwks.py
    Then follow the prompt to enter
    KMS Key ID:
