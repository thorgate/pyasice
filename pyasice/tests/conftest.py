from datetime import datetime, timedelta

import pytest

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509 import Certificate, NameOID

from pyasice import XmlSignature


@pytest.fixture()
def signed_data():
    return b"Just some data to sign"


@pytest.fixture()
def private_key_ec():
    return ec.generate_private_key(ec.SECP521R1(), default_backend())


@pytest.fixture()
def private_key_rsa():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())


def cert_builder(private_key, subject="signing user", issuer="issuer CA"):
    """
    https://cryptography.io/en/latest/x509/reference/#x-509-certificate-builder
    """
    public_key = private_key.public_key()
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(
        x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, subject),
            ]
        )
    )
    builder = builder.issuer_name(
        x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, issuer),
            ]
        )
    )
    builder = builder.not_valid_before(datetime.today())
    builder = builder.not_valid_after(datetime.today() + timedelta(days=5))
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.public_key(public_key)
    builder = builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True,
    )
    certificate = builder.sign(private_key=private_key, algorithm=hashes.SHA256(), backend=default_backend())
    return certificate


@pytest.fixture()
def certificate_ec(private_key_ec) -> Certificate:
    return cert_builder(private_key_ec)


@pytest.fixture()
def certificate_rsa(private_key_rsa) -> Certificate:
    return cert_builder(private_key_rsa)


def generate_xml_signature(certificate: Certificate, signature_algo=None):
    return (
        XmlSignature.create()
        .set_signature_algorithm(signature_algo)
        .add_document("test.txt", b"test", "text/plain")
        .set_certificate(certificate.public_bytes(Encoding.DER))
        .update_signed_info()
    )


@pytest.fixture()
def xml_signature_rsa_signed(certificate_rsa, private_key_rsa):
    s = generate_xml_signature(certificate_rsa)
    signed_data = s.signed_data()

    signature = private_key_rsa.sign(signed_data, padding.PKCS1v15(), hashes.SHA256())

    s.set_signature_value(signature)
    return s
