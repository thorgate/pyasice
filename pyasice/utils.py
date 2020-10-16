from .container import Container
from .exceptions import NoFilesToSign
from .ocsp import OCSP
from .tsa import TSA
from .xmlsig import XmlSignature


def prepare_signature(user_certificate: bytes, root_certificate: bytes, container: Container) -> XmlSignature:
    """Generate the XAdES signature structure

    :param user_certificate: the DER-encoded user certificate
    :param root_certificate: the DER-encoded root certificate
    :param container: The BDoc2 container to operate on
    """
    if not container.has_data_files():
        raise NoFilesToSign(f"Container `{container}` contains no files to sign")

    # Generate a XAdES signature
    xml_sig = XmlSignature.create()

    for file_name, content, mime_type in container.iter_data_files():
        xml_sig.add_document(file_name, content, mime_type)

    xml_sig.set_certificate(user_certificate).set_root_ca_cert(root_certificate).update_signed_info()

    return xml_sig


def finalize_signature(xml_signature: XmlSignature, lt_ts=False):
    """Finalize the XAdES signature in accordance with LT-TM profile, or LT-TS profile if `lt_ts` is True

    :param XmlSignature xml_signature:
    :param bool lt_ts: Whether to make the signature compliant with LT-TS and perform a TSA request
    """
    subject_cert = xml_signature.get_certificate()
    issuer_cert = xml_signature.get_root_ca_cert()

    # Get an OCSP status confirmation
    ocsp = OCSP(url=OCSP.DEMO_URL if is_demo else None)
    ocsp.validate(subject_cert, issuer_cert, xml_signature.get_signature_value())

    # Embed the OCSP response
    xml_signature.set_ocsp_response(ocsp)

    if lt_ts:
        # Get a signature TimeStamp
        tsa = TSA(url=TSA.DEMO_URL if is_demo else None)
        tsr = tsa.get_timestamp(xml_signature.get_timestamp_response())
        xml_signature.set_timestamp_response(tsr)
    else:
        xml_signature.remove_timestamp_node()
