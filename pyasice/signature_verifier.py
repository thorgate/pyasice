from asn1crypto.core import Integer, Sequence
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.x509 import Certificate, load_der_x509_certificate

from .exceptions import InvalidSignatureAlgorithm, SignatureVerificationError


class ECDSASignature(Sequence):
    """
    Represents a DER-encoded ECDSA signature sequence
    """

    _fields = [
        ("r", Integer),
        ("s", Integer),
    ]


def x962_to_der(signature: bytes):
    """
    Convert binary signature (X9.62 format) into a DER encoded one.

    X.962 is a raw big-endian concatenation of two 32 byte long primes.
    """
    num_length = len(signature) // 2
    r_prime, s_prime = [int.from_bytes(x, "big") for x in (signature[:num_length], signature[num_length:])]

    return ECDSASignature({"r": r_prime, "s": s_prime}).dump()


def verify(certificate, signature, data, hash_algo="SHA256", prehashed=False):
    """Verify RSA and EC signatures with the cryptography library

    :param Union[bytes, Certificate] certificate:
    :param bytes signature:
    :param bytes data: the original signed data, or its hash
    :param hash_algo:
    :param prehashed: True if `data` is a hash of original signed data instead
    :return:
    """
    if not isinstance(certificate, Certificate):
        certificate = load_der_x509_certificate(certificate, default_backend())

    hash_algo = hash_algo.upper()
    if hash_algo not in ("SHA256", "SHA384", "SHA512"):
        raise InvalidSignatureAlgorithm(hash_algo)

    hasher = getattr(hashes, hash_algo)
    chosen_hash = hasher()
    if prehashed:
        chosen_hash = Prehashed(chosen_hash)

    public_key = certificate.public_key()

    try:
        if isinstance(public_key, ec.EllipticCurvePublicKey):
            # the `verify()` method expects a DER-encoded signature,
            # but we may get an X.962 encoded one depending on the service.
            try:
                # DER encoding is a strict format, so try loading it first.
                # It contains various constant fields, which together take 8 bytes,
                # (if both `r` and `s` numbers are 32 bytes long, DER takes 72 bytes instead of 64)
                # so coincidence with a valid X.962 signature is highly improbable
                ECDSASignature.load(signature)
            except ValueError:
                signature = x962_to_der(signature)

            public_key.verify(signature, data, ec.ECDSA(chosen_hash))
        else:
            public_key.verify(signature, data, padding.PKCS1v15(), chosen_hash)
    except InvalidSignature:
        raise SignatureVerificationError()
