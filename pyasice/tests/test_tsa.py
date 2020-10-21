import hashlib
from unittest.mock import Mock, patch

import pytest
from asn1crypto.cms import ContentInfo

from asn1crypto.ocsp import OCSPRequest
from asn1crypto.x509 import Certificate as ASN1Certificate
from cryptography.hazmat.primitives.serialization import Encoding
from oscrypto.asymmetric import load_certificate

from pyasice.tsa import TSA, requests

from .conftest import cert_builder


class MockResponse(Mock):
    status_code = 200
    headers = {"Content-Type": TSA.RESPONSE_CONTENT_TYPE}


def test_tsa_build_message_imprint():
    assert TSA.build_message_imprint(b'test') == {
        "hash_algorithm": {"algorithm": "sha256"},
        "hashed_message": hashlib.sha256(b'test').digest(),
    }


def test_tsa_get_timestamp(demo_ts_response):
    tsa = TSA("http://dummy.url")

    with patch.object(tsa, 'build_ts_request') as mock_build_ts_request:
        mock_build_ts_request.return_value = Mock()
        mock_build_ts_request.return_value.dump.return_value = "Mock TSA Request"

        with patch.object(requests, "post") as mock_post:
            mock_post.return_value = response = MockResponse()
            response.content = demo_ts_response
            ts_response = tsa.get_timestamp(b'test')
            assert isinstance(ts_response, ContentInfo)

    mock_build_ts_request.assert_called_once_with(b'test')
    mock_post.assert_called_once_with("http://dummy.url", data="Mock TSA Request", headers={
        "Content-Type": TSA.REQUEST_CONTENT_TYPE,
        "Connection": "close",
    })


def test_tsa_existing_response(demo_xml_signature, demo_ts_response):
    TSA.verify(demo_ts_response, demo_xml_signature.signed_data())
