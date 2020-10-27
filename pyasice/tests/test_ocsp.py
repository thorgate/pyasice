from unittest.mock import Mock, patch

import pytest

from asn1crypto.ocsp import OCSPRequest
from asn1crypto.x509 import Certificate as ASN1Certificate
from cryptography.hazmat.primitives.serialization import Encoding
from oscrypto.asymmetric import load_certificate

from pyasice.ocsp import OCSP, requests

from .conftest import cert_builder


class MockResponse(Mock):
    status_code = 200
    headers = {"Content-Type": OCSP.RESPONSE_CONTENT_TYPE}


@pytest.mark.parametrize("signature", [None, b"some-signature-bytes"])
def test_ocsp_build_request(private_key_rsa, certificate_rsa, signature):
    issuer_cert = cert_builder(private_key_rsa, subject="issuer CA", issuer="CA").public_bytes(Encoding.DER)
    subject_cert = certificate_rsa.public_bytes(Encoding.DER)
    resp = OCSP.build_ocsp_request(subject_cert, issuer_cert, signature=signature)
    assert isinstance(resp, OCSPRequest)

    issuer_cert = load_certificate(issuer_cert)
    subject_cert = load_certificate(subject_cert)
    resp = OCSP.build_ocsp_request(subject_cert, issuer_cert, signature=signature)
    assert isinstance(resp, OCSPRequest)

    issuer_cert = issuer_cert.asn1
    subject_cert = subject_cert.asn1
    resp = OCSP.build_ocsp_request(subject_cert, issuer_cert, signature=signature)
    assert isinstance(resp, OCSPRequest)


def test_ocsp_existing_response(demo_ocsp_response):
    ocsp_resp = OCSP.load(demo_ocsp_response)
    assert isinstance(ocsp_resp, OCSP)

    certs = ocsp_resp.get_responder_certs()
    assert len(certs) > 0
    assert isinstance(certs[0], ASN1Certificate)

    assert certs[0].subject.native["common_name"] == "TEST of SK OCSP RESPONDER 2011"
    assert certs[0].issuer.native["common_name"] == "TEST of EE Certification Centre Root CA"

    OCSP.verify_response(ocsp_resp.get_encapsulated_response())
    ocsp_resp.verify()


def test_ocsp_validate(demo_ocsp_response):
    ocsp = OCSP("http://dummy.url")
    with patch.object(ocsp, "build_ocsp_request") as mock_build_ocsp_request:
        mock_build_ocsp_request.return_value = Mock()
        mock_build_ocsp_request.return_value.dump.return_value = "Mock OCSP Request"

        with patch.object(requests, "post") as mock_post:
            mock_post.return_value = response = MockResponse()
            response.content = demo_ocsp_response
            ocsp.validate(b"subject cert", b"issuer cert", b"some-signature")

    mock_build_ocsp_request.assert_called_once_with(b"subject cert", b"issuer cert", b"some-signature")
    mock_post.assert_called_once_with(
        "http://dummy.url",
        data="Mock OCSP Request",
        headers={"Content-Type": OCSP.REQUEST_CONTENT_TYPE, "Connection": "close"},
    )
