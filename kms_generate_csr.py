import argparse
import boto3
import hashlib
import textwrap
from dotenv import load_dotenv
from base64 import b64encode
from pyasn1.type import univ, char
from pyasn1_modules.rfc2986 import CertificationRequest, CertificationRequestInfo
from pyasn1_modules.rfc2314 import SubjectPublicKeyInfo, SignatureAlgorithmIdentifier
from pyasn1_modules import rfc2459
from pyasn1.codec.der import decoder, encoder


load_dotenv()  # take environment variables from .env.

START_MARKER = "-----BEGIN CERTIFICATE REQUEST-----"
END_MARKER = "-----END CERTIFICATE REQUEST-----"

SIGNING_ALGORITHM_OID = {
    "ECDSA_SHA_512": "1.2.840.10045.4.3.4",
    "ECDSA_SHA_384": "1.2.840.10045.4.3.3",
    "ECDSA_SHA_256": "1.2.840.10045.4.3.2",
    "ECDSA_SHA_224": "1.2.840.10045.4.3.1",
    "RSASSA_PKCS1_V1_5_SHA_512": "1.2.840.113549.1.1.13",
    "RSASSA_PKCS1_V1_5_SHA_384": "1.2.840.113549.1.1.12",
    "RSASSA_PKCS1_V1_5_SHA_256": "1.2.840.113549.1.1.11",
}

kms = boto3.client("kms")


def create_rdn(object_identifer: univ.ObjectIdentifier, value: str):
    if value is None or value == '.':
        value = ""
    attribute = rfc2459.AttributeTypeAndValue()
    attribute["type"] = object_identifer
    attribute["value"] = char.PrintableString(value)
    rdn = rfc2459.RelativeDistinguishedName()
    rdn.append(attribute)
    return rdn


def create_subject():
    print("""you are about to be asked to enter information that will be incorporated
    into your certificate request.
    What you are about to enter is what is called a Distinguished Name or a DN.
    There are quite a few fields but you can leave some blank
    For some fields there will be a default value,
    If you enter '.', the field will be left blank. """)

    countryName = input("Country Name (2 letter code) [XX]:")
    stateOrProvinceName = input("State or Province Name (full name) []:")
    localityName = input("Locality Name (eg, city) [Default City]:")
    organizationName = input(
        "Organization Name (eg, company) [Default Company Ltd]:")
    organizationalUnitName = input(
        "Organizational Unit Name (eg, section) []:")
    commonName = input(
        "Common Name (eg, your name or your server's hostname) []:")
    emailAddress = input("Email Address []:")

    dn = rfc2459.Name()
    dn[0] = rfc2459.RDNSequence()
    dn[0].append(create_rdn(rfc2459.id_at_countryName, countryName))
    dn[0].append(create_rdn(
        rfc2459.id_at_stateOrProvinceName, stateOrProvinceName))
    dn[0].append(create_rdn(rfc2459.id_at_localityName, localityName))
    dn[0].append(create_rdn(rfc2459.id_at_organizationName, organizationName))
    dn[0].append(create_rdn(
        rfc2459.id_at_organizationalUnitName, organizationalUnitName))
    dn[0].append(create_rdn(rfc2459.id_at_commonName, commonName))
    dn[0].append(create_rdn(rfc2459.emailAddress, emailAddress))

    return dn


def generate_csr(key_id, signing_algorithm):
    cri = CertificationRequestInfo()
    cri["version"] = 0
    cri["subject"] = create_subject()

    response = kms.get_public_key(KeyId=key_id)
    cri["subjectPKInfo"] = decoder.decode(
        response["PublicKey"], SubjectPublicKeyInfo())[0]

    der_bytes = encoder.encode(cri)
    hash_algorithm = "".join(signing_algorithm.split("_")[-2:]).lower()
    digest = hashlib.new(hash_algorithm, der_bytes)
    res = kms.sign(
        KeyId=key_id,
        Message=digest.digest(),
        MessageType="DIGEST",
        SigningAlgorithm=signing_algorithm,
    )
    signature = res["Signature"]

    csr = CertificationRequest()
    csr["certificationRequestInfo"] = cri
    sai = SignatureAlgorithmIdentifier()
    sai["algorithm"] = univ.ObjectIdentifier(
        SIGNING_ALGORITHM_OID[signing_algorithm])
    csr["signatureAlgorithm"] = sai
    csr["signature"] = univ.BitString.fromOctetString(signature)

    return csr


def write_csr(csr, filename):
    b64csr = b64encode(encoder.encode(csr)).decode()
    s = "\n".join([START_MARKER, "\n".join(textwrap.wrap(b64csr)), END_MARKER])
    with open(filename, "w") as file:
        file.write(s)
    print(s)


def main(args):
    key_id = input("KMS Key ID:")
    signing_algorithm = "RSASSA_PKCS1_V1_5_SHA_256"
    csr = generate_csr(key_id, signing_algorithm)
    write_csr(csr, "cert_sign_request.csr")


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    args = parser.parse_args()
    main(args)
