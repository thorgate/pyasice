import os
from unittest.mock import patch

import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509 import load_pem_x509_certificate

p = os.path
CERTS_PATH = p.abspath(p.join(p.dirname(__file__), 'certificates'))


@pytest.fixture()
def certificate_ecdsa_file():
    return p.join(CERTS_PATH, 'ecdsa.pem')


@pytest.fixture()
def certificate_rsa_file():
    return p.join(CERTS_PATH, 'rsa.pem')


@pytest.fixture()
def signed_data():
    return b'Just some data to sign'


@pytest.fixture()
def private_key_ec():
    return ec.generate_private_key(
        ec.SECP521R1(),
        default_backend()
    )


@pytest.fixture()
def private_key_rsa():
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )


@pytest.fixture()
def certificate_ec(certificate_ecdsa_file, private_key_ec):
    """
    Can also build a real certificate:
    https://cryptography.io/en/latest/x509/reference/#x-509-certificate-builder
    """
    with open(certificate_ecdsa_file, 'rb') as f:
        cert_pem = f.read()
    cert = load_pem_x509_certificate(cert_pem, default_backend())

    with patch.object(cert, 'public_key') as fake_public_key:
        fake_public_key.return_value = private_key_ec.public_key()
        yield cert


@pytest.fixture()
def certificate_rsa(certificate_rsa_file, private_key_rsa):
    with open(certificate_rsa_file, 'rb') as f:
        cert_pem = f.read()
    cert = load_pem_x509_certificate(cert_pem, default_backend())

    with patch.object(cert, 'public_key') as fake_public_key:
        fake_public_key.return_value = private_key_rsa.public_key()
        yield cert

