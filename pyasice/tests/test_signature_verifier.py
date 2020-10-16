import hashlib

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding

from ..signature_verifier import verify, ECDSASignature


def der_to_x962(signature):
    der_seq = ECDSASignature.load(signature)
    r_prime, s_prime = int(der_seq['r']), int(der_seq['s'])
    buf = []
    for num in (s_prime, r_prime):
        for _ in range(66):  # each prime should be exactly 66 bytes for the 521-bit EC
            lowest_byte = num & 0xFF
            buf.append(int(lowest_byte))
            num >>= 8
    return bytes(reversed(buf))


@pytest.fixture()
def signed_data():
    return b'Just some data to sign'


@pytest.mark.parametrize('x962', [True, False])
def test_verify_data_ec(private_key_ec, certificate_ec, signed_data, x962):
    signature = private_key_ec.sign(signed_data, ec.ECDSA(hashes.SHA256()))

    assert certificate_ec.public_key().public_numbers() == private_key_ec.public_key().public_numbers()

    private_key_ec.public_key().verify(signature, signed_data, ec.ECDSA(hashes.SHA256()))

    if x962:
        signature = der_to_x962(signature)

    verify(certificate_ec, signature, signed_data)
    assert "No exception was raised by the previous call"


@pytest.mark.parametrize('x962', [True, False])
def test_verify_hash_ec(private_key_ec, certificate_ec, signed_data, x962):
    signature = private_key_ec.sign(signed_data, ec.ECDSA(hashes.SHA256()))

    assert certificate_ec.public_key().public_numbers() == private_key_ec.public_key().public_numbers()

    private_key_ec.public_key().verify(signature, signed_data, ec.ECDSA(hashes.SHA256()))

    prehash = hashlib.sha256(signed_data).digest()

    if x962:
        signature = der_to_x962(signature)

    verify(certificate_ec, signature, prehash, prehashed=True)
    assert "No exception was raised by the previous call"


def test_verify_data_rsa(private_key_rsa, certificate_rsa, signed_data):
    signature = private_key_rsa.sign(
        signed_data,
        padding.PKCS1v15(),
        hashes.SHA256()
    )

    private_key_rsa.public_key().verify(signature, signed_data, padding.PKCS1v15(), hashes.SHA256())

    verify(certificate_rsa, signature, signed_data)
    assert "No exception was raised by the previous call"
