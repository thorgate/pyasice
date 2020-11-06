from .exceptions import PyAsiceError
from .ocsp import OCSP
from .tsa import TSA
from .xmlsig import XmlSignature


def finalize_signature(xml_signature: XmlSignature, issuer_cert: bytes, lt_ts=True, *, ocsp_url, tsa_url=None):
    """Finalize the XAdES signature in accordance with LT-TM profile, or LT-TS profile if `lt_ts` is True

    :param XmlSignature xml_signature:
    :param bytes issuer_cert:
    :param bool lt_ts: Whether to make the signature compliant with LT-TS and perform a TSA request
    :param ocsp_url:
    :param tsa_url: required if lt_ts is True
    """
    if lt_ts and not tsa_url:
        raise ValueError("TSA URL can not be empty when LT-TS profile is selected, requires a TSA service query")

    signature_value = xml_signature.get_signature_value()
    if not signature_value:
        raise PyAsiceError("The XML signature has not been signed properly")

    subject_cert = xml_signature.get_certificate()

    if lt_ts:
        # Get a signature TimeStamp
        tsa = TSA(tsa_url)
        tsr = tsa.get_timestamp(xml_signature.get_timestamped_message())
        xml_signature.set_timestamp_response(tsr)
    else:
        xml_signature.remove_timestamp_node()

    # Get an OCSP status confirmation
    ocsp = OCSP(ocsp_url)
    ocsp.validate(subject_cert, issuer_cert, signature_value)

    # Embed the OCSP response
    xml_signature.set_ocsp_response(ocsp)
