from unittest.mock import patch

from cryptography.hazmat.primitives.serialization import Encoding

from pyasice import finalize_signature
from pyasice.ocsp import OCSP
from pyasice.tsa import TSA


@patch.object(OCSP, "load")
@patch.object(OCSP, "validate")
@patch.object(OCSP, "get_encapsulated_response")
@patch.object(TSA, "get_timestamp")
def test_utils_finalize_signature(
    mock_tsa_get_timestamp,
    mock_ocsp_get_encapsulated_response,
    mock_ocsp_validate,
    mock_ocsp_load,
    certificate_rsa,
    xml_signature_rsa_signed,
):
    assert xml_signature_rsa_signed.get_ocsp_response() is None
    assert xml_signature_rsa_signed.get_timestamp_response() is None

    mock_tsa_get_timestamp.return_value.dump.return_value = b"Mock TSA Response"
    mock_ocsp_get_encapsulated_response.return_value = b"Mock OCSP Response"
    mock_ocsp_load.side_effect = lambda x: x

    issuer_cert_bytes = certificate_rsa.public_bytes(Encoding.DER)

    finalize_signature(
        xml_signature_rsa_signed,
        issuer_cert=issuer_cert_bytes,
        lt_ts=True,
        ocsp_url="http://dummy.ocsp.url",
        tsa_url="http://dummy.tsa.url",
    )

    mock_ocsp_validate.assert_called_once_with(
        xml_signature_rsa_signed.get_certificate(),
        issuer_cert_bytes,
        xml_signature_rsa_signed.get_signature_value(),
    )

    mock_tsa_get_timestamp.assert_called_once_with(xml_signature_rsa_signed.get_timestamped_message())

    assert xml_signature_rsa_signed.get_ocsp_response() == b"Mock OCSP Response"
    assert xml_signature_rsa_signed.get_timestamp_response() == b"Mock TSA Response"
