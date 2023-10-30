from cryptography.hazmat.primitives import serialization
import json
import boto3
import base64
import argparse
import uuid
kms_client = boto3.client('kms')


def kms_public_key_to_jwks(key_id):
    # Get the public key from the KMS key pair
    response = kms_client.get_public_key(KeyId=key_id)

    public_key_data = response['PublicKey']
    # Parse the DER-encoded public key
    public_key = serialization.load_der_public_key(
        public_key_data, backend=None)

    rsa_public_numbers = public_key.public_numbers()
    # Base64URL-encode the 'n' and 'e' values
    n_base64url = base64.urlsafe_b64encode(rsa_public_numbers.n.to_bytes(
        (rsa_public_numbers.n.bit_length() + 7) // 8, 'big')).rstrip(b'=').decode('utf-8')
    e_base64url = base64.urlsafe_b64encode(rsa_public_numbers.e.to_bytes(
        (rsa_public_numbers.e.bit_length() + 7) // 8, 'big')).rstrip(b'=').decode('utf-8')

    # Generate a Key ID (kid)
    kid = str(uuid.uuid4())

    # Create a JSON Web Key (JWK) object and print it
    jwk = {
        "kty": "RSA",
        "alg": "RS256",
        "use": "sig",  # Use "sig" for a signing key
        "n": n_base64url,
        "e": e_base64url,
        "kid": kid  # Add the Key ID
    }

    # Convert the JWK to a JWKS (JSON Web Key Set)
    jwks = {"keys": [jwk]}

    # Print the JWKS in JSON format
    print(json.dumps(jwks, indent=2))


def main(args):
    key_id = input("KMS Key ID:")
    kms_public_key_to_jwks(key_id)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    args = parser.parse_args()
    main(args)
