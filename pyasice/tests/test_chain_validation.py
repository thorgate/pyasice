"""
Tests demonstrating missing certificate chain validation (Issue #17).

These tests PASS but SHOULD FAIL - they prove that pyasice accepts signatures from:
- Self-signed certificates
- Expired certificates
- Certificates signed by untrusted CAs

Each test is marked with pytest.mark.xfail(reason="...") to document expected behavior.
When chain validation is implemented, these tests should start failing (which means
the xfail marks should be removed and assertions inverted).
"""

from datetime import datetime, timedelta

import pytest

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509 import NameOID

from pyasice import XmlSignature


def generate_key_pair():
    """Generate a new RSA key pair."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    return private_key


def create_self_signed_cert(private_key, subject="Test User", days_valid=5):
    """Create a self-signed certificate (subject signs itself)."""
    public_key = private_key.public_key()
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, subject),
    ]))
    # Self-signed: issuer == subject
    builder = builder.issuer_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, subject),
    ]))
    builder = builder.not_valid_before(datetime.today())
    builder = builder.not_valid_after(datetime.today() + timedelta(days=days_valid))
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.public_key(public_key)
    builder = builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True,
    )
    # Signed with own private key = self-signed
    certificate = builder.sign(
        private_key=private_key,
        algorithm=hashes.SHA256(),
        backend=default_backend()
    )
    return certificate


def create_expired_cert(private_key, subject="Expired User"):
    """Create a certificate that expired yesterday."""
    public_key = private_key.public_key()
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, subject),
    ]))
    builder = builder.issuer_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "Some CA"),
    ]))
    # Expired: was valid 10 days ago, expired yesterday
    builder = builder.not_valid_before(datetime.today() - timedelta(days=10))
    builder = builder.not_valid_after(datetime.today() - timedelta(days=1))
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.public_key(public_key)
    builder = builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True,
    )
    certificate = builder.sign(
        private_key=private_key,
        algorithm=hashes.SHA256(),
        backend=default_backend()
    )
    return certificate


def create_untrusted_ca_cert(ca_key, subject_key, subject="User from Untrusted CA"):
    """Create a certificate signed by an untrusted CA."""
    # First create the "untrusted CA" certificate
    ca_builder = x509.CertificateBuilder()
    ca_builder = ca_builder.subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "Malicious CA"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Evil Corp"),
    ]))
    ca_builder = ca_builder.issuer_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "Malicious CA"),
    ]))
    ca_builder = ca_builder.not_valid_before(datetime.today())
    ca_builder = ca_builder.not_valid_after(datetime.today() + timedelta(days=365))
    ca_builder = ca_builder.serial_number(x509.random_serial_number())
    ca_builder = ca_builder.public_key(ca_key.public_key())
    ca_builder = ca_builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=0),
        critical=True,
    )

    # Now create a user certificate signed by this untrusted CA
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, subject),
    ]))
    builder = builder.issuer_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "Malicious CA"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Evil Corp"),
    ]))
    builder = builder.not_valid_before(datetime.today())
    builder = builder.not_valid_after(datetime.today() + timedelta(days=5))
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.public_key(subject_key.public_key())
    builder = builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True,
    )
    # Signed by the untrusted CA's key
    certificate = builder.sign(
        private_key=ca_key,
        algorithm=hashes.SHA256(),
        backend=default_backend()
    )
    return certificate


def sign_xml_signature(xml_sig, private_key):
    """Sign an XmlSignature with the given private key."""
    signed_data = xml_sig.signed_data()
    signature = private_key.sign(signed_data, padding.PKCS1v15(), hashes.SHA256())
    xml_sig.set_signature_value(signature)
    return xml_sig


class TestSelfSignedCertificateAccepted:
    """
    Demonstrates that self-signed certificates pass verification.

    A self-signed certificate has no chain of trust - it vouches for itself.
    This should be rejected unless explicitly trusted as a root.
    """

    @pytest.mark.xfail(
        reason="Chain validation not implemented - self-signed certs should be rejected",
        strict=True
    )
    def test_self_signed_cert_should_be_rejected(self):
        """Self-signed certificate should NOT pass signature verification."""
        private_key = generate_key_pair()
        cert = create_self_signed_cert(private_key, subject="Self-Signed User")

        xml_sig = (
            XmlSignature.create()
            .add_document("test.txt", b"test content", "text/plain")
            .set_certificate(cert.public_bytes(Encoding.DER))
            .update_signed_info()
        )
        sign_xml_signature(xml_sig, private_key)

        # This SHOULD raise an exception but currently doesn't
        xml_sig.verify()

        # If we reach here, the test "passes" but that's the bug
        pytest.fail("Self-signed certificate was accepted - chain validation missing")


class TestExpiredCertificateAccepted:
    """
    Demonstrates that expired certificates pass verification.

    An expired certificate should be rejected regardless of signature validity.
    """

    @pytest.mark.xfail(
        reason="Certificate expiration not checked during verification",
        strict=True
    )
    def test_expired_cert_should_be_rejected(self):
        """Expired certificate should NOT pass signature verification."""
        private_key = generate_key_pair()
        cert = create_expired_cert(private_key, subject="Expired User")

        xml_sig = (
            XmlSignature.create()
            .add_document("test.txt", b"test content", "text/plain")
            .set_certificate(cert.public_bytes(Encoding.DER))
            .update_signed_info()
        )
        sign_xml_signature(xml_sig, private_key)

        # This SHOULD raise an exception but currently doesn't
        xml_sig.verify()

        # If we reach here, the test "passes" but that's the bug
        pytest.fail("Expired certificate was accepted - expiration check missing")


class TestUntrustedCAAccepted:
    """
    Demonstrates that certificates from untrusted CAs pass verification.

    A certificate signed by an unknown/untrusted CA should be rejected
    because there's no chain of trust to a known root.
    """

    @pytest.mark.xfail(
        reason="Chain validation not implemented - untrusted CA certs should be rejected",
        strict=True
    )
    def test_untrusted_ca_cert_should_be_rejected(self):
        """Certificate from untrusted CA should NOT pass signature verification."""
        ca_key = generate_key_pair()
        user_key = generate_key_pair()
        cert = create_untrusted_ca_cert(ca_key, user_key, subject="User from Evil Corp")

        xml_sig = (
            XmlSignature.create()
            .add_document("test.txt", b"test content", "text/plain")
            .set_certificate(cert.public_bytes(Encoding.DER))
            .update_signed_info()
        )
        sign_xml_signature(xml_sig, user_key)

        # This SHOULD raise an exception but currently doesn't
        xml_sig.verify()

        # If we reach here, the test "passes" but that's the bug
        pytest.fail("Certificate from untrusted CA was accepted - chain validation missing")


class TestExistingTestsUseSelfSignedCerts:
    """
    Documents that the existing test suite uses self-signed certificates.

    The conftest.py cert_builder() creates certificates where:
    - subject = "signing user"
    - issuer = "issuer CA"
    - BUT it's signed with the subject's own private key

    This is effectively self-signed (the issuer name is a lie).
    These pass because only cryptographic verification is performed.
    """

    def test_existing_fixture_is_self_signed(self, certificate_rsa, private_key_rsa):
        """
        Prove that the existing test fixture creates self-signed certificates.

        The certificate claims issuer="issuer CA" but is signed with the
        subject's private key, making it cryptographically self-signed.
        """
        # The certificate says it was issued by "issuer CA"
        issuer_cn = certificate_rsa.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        assert issuer_cn == "issuer CA"

        # But it's actually signed with the subject's own key
        subject_cn = certificate_rsa.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        assert subject_cn == "signing user"

        # Verify the certificate signature using the subject's own public key
        # (this would fail if it was truly signed by a different "issuer CA")
        public_key = private_key_rsa.public_key()
        public_key.verify(
            certificate_rsa.signature,
            certificate_rsa.tbs_certificate_bytes,
            padding.PKCS1v15(),
            certificate_rsa.signature_hash_algorithm,
        )
        # If we get here, the certificate is self-signed (signed with subject's key)
        # A proper certificate would need the issuer CA's key to verify