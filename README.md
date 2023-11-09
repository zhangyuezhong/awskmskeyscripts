# kms scripts

 1. **kms_generate_csr.py** This script enables the creation of a Certificate Signing Request (CSR) that utilizes the Asymmetric Key stored in KMS. The CSR can then be signed by your Public Key Infrastructure (PKI). This process allows you to sign arbitrary data using KMS while preserving the security of your private key, which remains protected within KMS. It's important to note that this script does not sign the CSR with a Certificate Authority (CA) to transform it into an officially recognized certificate. Instead, the CSR is signed with the private key of the generator to demonstrate ownership of the public key, as required by the CA, and this script re-signs it using the private key stored in KMS.
 2. **kms_public_key_to_jwks.py** This script facilitates the transformation of the public key associated with an Asymmetric Key into a JSON Web Key Set (JWKS)

## Installation

    git clone https://github.com/zhangyuezhong/awskmskeyscripts.git

## create a new virtualenv

    cd generate_csr_with_kms
    python3 -m venv venv
    # Please execute the following command on a Windows system:
    venv\Scripts\activate.bat
    # Please execute the following command on a Liux system:
    . venv/bin/activate

## install prerequisite modules

    pip3 install -r requirements.txt


## Notes.
Ensure that the AWS credentials have the necessary permissions to utilize the KMS key.

# Create CSR with KMS Asymmetric key
    python kms_generate_csr.py
    Then follow the prompt to enter
    KMS Key ID:

# Convert the public key of KMS Asymmetric key to JWKS
    python kms_public_key_to_jwks.py
    Then follow the prompt to enter
    KMS Key ID:

# Use Case 1

  
If you have a Lambda function that needs to access data from ServiceNow and you have set up an OAuth JWT API endpoint for external clients as described in the [Create an OAuth JWT API endpoint for external clients](https://docs.servicenow.com/en-US/bundle/vancouver-platform-security/page/administer/security/task/create-jwt-endpoint.html) documentation, you can take the following steps:

1.  Create an Asymmetric Key Pair (for signing and verification) in AWS KMS.
2.  Utilize the `kms_generate_csr.py` script to generate a Certificate Signing Request (CSR), which is subsequently signed by your PKI team.
3.  Import the signed certificate back into ServiceNow.
4.  Your Lambda function can leverage the private key stored in AWS KMS to sign the JWT header and payload, creating a secure assertion for use in your interactions with the ServiceNow OAuth JWT API endpoint.

# Use Case 2

If you have a Lambda function that requires access to data from Okta and you've configured OAuth as outlined in [Implement OAuth for Okta with a service app](https://developer.okta.com/docs/guides/implement-oauth-for-okta-serviceapp/main/), you can implement the following steps:

1.  Instead of storing the private key in an insecure location, you can utilize AWS Key Management Service (KMS) to generate an Asymmetric Key Pair, ensuring that the private key remains secure within KMS.
    
2.  Your Lambda function can then utilize this private key from KMS to sign the JWT header and payload for authentication.
    
3.  You can import the corresponding public key into your Okta configuration. However, Okta specifically requires the public key to be in JWKS (JSON Web Key Set) format.
    
4.  To meet Okta's requirements, you can use the `kms_public_key_to_jwks.py` script to convert the public key into JWKS format. After this conversion, you can add the key to your Okta configuration, ensuring compatibility and security.


# Credit to
"How to Replace the Signature of an Issued CSR
GitHub g-a-d/aws-kms-sign-csr -- https://github.com/g-a-d/aws-kms-sign-csr"
AWS KMSでCSRを発行する  https://qiita.com/nobrin/items/85c37f9b0d6245a1a2e4