import base64
import copy
import hashlib
import logging
import os
from datetime import datetime
from typing import Dict, Optional, Union

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from lxml import etree
from oscrypto.asymmetric import Certificate, load_certificate

from .exceptions import SignatureVerificationError
from .ocsp import OCSP
from .signature_verifier import verify
from .tsa import TSA


logger = logging.getLogger(__name__)


def get_utc_time():
    # For testing purposes, as we can't patch a datetime object
    return datetime.utcnow()


class XmlSignature:
    """
    Usage:

        # Create a signature XAdES structure
        sig = XmlSignature.create() \
            .add_document('test.pdf', b'PDF data', 'application/pdf') \
            .set_certificate(file_or_binary_data) \
            .update_signed_info()

        # Get the actual signature from e.g. smartid, out of scope
        signature_value = sign(id_code, sig.digest())

        # Get OCSP and TSA confirmation
        result_xml = sig.set_signature_value(signature_value) \
            .verify() \
            .set_ocsp_response(...) \
            .set_timestamp_response(...) \
            .dump()

        # or:
        from .utils import finalize_signature
        finalize_signature(sig, lt_ts=True)
    """

    SIGNATURE_TEMPLATE = os.path.join(os.path.dirname(__file__), "templates", "signature.xml")
    NAMESPACES = {
        "asic": "http://uri.etsi.org/02918/v1.2.1#",
        "ds": "http://www.w3.org/2000/09/xmldsig#",
        "xades": "http://uri.etsi.org/01903/v1.3.2#",
    }

    C14N_METHODS = (
        "http://www.w3.org/TR/2001/REC-xml-c14n-20010315",  # this is the REQUIRED c14n algorithm [xmldsig]
        "http://www.w3.org/2001/10/xml-exc-c14n#",
        "http://www.w3.org/2006/12/xml-c14n11",
    )

    DIGEST_ALGORITHMS = {
        "sha256": "http://www.w3.org/2001/04/xmlenc#sha256",
    }

    # https://www.w3.org/TR/xmldsig-core1/#sec-AlgID
    SIGNATURE_ALGO_ID_TEMPLATE = "http://www.w3.org/2001/04/xmldsig-more#{algo}"
    SIGNATURE_ALGORITHMS = [
        "rsa-sha256",  # the default one, is embedded in the XML template.
        "ecdsa-sha256",
        "rsa-sha384",
        "ecdsa-sha384",
        "rsa-sha512",
        "ecdsa-sha512",
    ]

    SIGNED_PROPERTIES_TYPE = (
        # Standards are ambiguous about this:
        "http://uri.etsi.org/01903#SignedProperties",  # BDOC 2.1.2 mandates this
        "http://uri.etsi.org/01903/v1.1.1#SignedProperties",  # and this is as per https://www.w3.org/TR/XAdES/
    )

    NEW_SIGNATURE_ID = "S1"  # This is arbitrary but used a few times in the XAdES structure.

    def __init__(self, xml_or_binary_data):
        if isinstance(xml_or_binary_data, (etree._Element, etree._ElementTree)):
            self.xml = xml_or_binary_data
        else:
            parser = etree.XMLParser(remove_blank_text=True, remove_comments=True)
            try:
                self.xml = etree.XML(xml_or_binary_data, parser=parser)
            except ValueError:
                logger.exception("Failed to load XML document: %s", xml_or_binary_data)
                raise

        if self.xml.tag != "{%s}XAdESSignatures" % self.NAMESPACES["asic"]:
            raise ValueError("Expecting an 'asic:XAdESSignatures' root node")

        data_objects_props_node = self._get_node("ds:SignedInfo")
        doc_entries = data_objects_props_node.findall('ds:Reference[@Type=""]', namespaces=self.NAMESPACES)
        self.doc_ids = [doc_entry.attrib["Id"] for doc_entry in doc_entries]

        self._certificate: Certificate = None
        self._prepared = None

    @classmethod
    def create(cls):
        """Create a XAdES structure from the accompanying template"""
        with open(cls.SIGNATURE_TEMPLATE, "rb") as f:
            xml_sig = cls(f.read().replace(b"{SIGNATURE_ID}", cls.NEW_SIGNATURE_ID.encode("ascii")))
            xml_sig.doc_ids = []
            return xml_sig

    def dump(self):
        return b'<?xml version="1.0" encoding="UTF-8"?>' + etree.tostring(self.xml)

    def get_signing_time(self):
        time_node = self._get_signing_time_node()
        if time_node is None or not time_node.text:
            return None
        return time_node.text

    def get_certificate(self) -> Certificate:
        if not self._certificate:
            cert_asn1 = self.get_certificate_value()
            if cert_asn1:
                # cache it on the instance, may be used a few times
                self._certificate = load_certificate(cert_asn1)
        return self._certificate

    def get_certificate_value(self):
        cert_node = self._get_node("ds:X509Certificate")
        if cert_node is None or not cert_node.text:
            return None
        return base64.b64decode(cert_node.text)

    def get_certificate_issuer_common_name(self):
        subject_cert = self.get_certificate()
        return subject_cert.asn1.issuer.native["common_name"] if subject_cert else None

    def set_certificate(self, subject_cert: Union[bytes, Certificate]):
        """Set the signer's certificate

        :param subject_cert: bytes, file name (Python 3.4+), asn1crypto.x509.Certificate objects
        """
        if not isinstance(subject_cert, Certificate):
            subject_cert = load_certificate(subject_cert)

        # cache it on the instance, may be used a few times
        self._certificate = subject_cert

        cert_asn1 = subject_cert.asn1
        der_encoded_cert = cert_asn1.dump()
        serial_number = ("%d" % cert_asn1.serial_number).encode("ascii")

        cert_node = self._get_node("ds:X509Certificate")
        cert_node.text = base64.b64encode(der_encoded_cert)

        cert_props = self._get_node("xades:SigningCertificate")
        cert_props.find(".//ds:DigestValue", self.NAMESPACES).text = base64.b64encode(cert_asn1.sha256)
        cert_props.find(".//ds:X509SerialNumber", self.NAMESPACES).text = serial_number

        # No idea what value is possible, but rfc4514 is most common, so get it from a cryptography object
        x509_cert = x509.load_der_x509_certificate(der_encoded_cert, default_backend())
        cert_props.find(".//ds:X509IssuerName", self.NAMESPACES).text = x509_cert.issuer.rfc4514_string()

        return self

    def add_document(self, file_name, binary_data, mime_type, hash_type="sha256") -> "XmlSignature":
        """Add a document for signing

        :param file_name: the file name to display in the container
        :param mime_type: the document's mime type
        :param binary_data: the document's contents
        :param hash_type: the hash function to use for digesting
        :return:
        """
        try:
            digest_algo = self.DIGEST_ALGORITHMS[hash_type]
        except KeyError as e:
            raise ValueError("Unknown hash type: %s" % hash_type) from e

        digest_fn = getattr(hashlib, hash_type)
        doc_hash = digest_fn(binary_data).digest()

        signed_info = self._get_node("ds:SignedInfo")
        first_ref_entry = signed_info.find('.//ds:Reference[@Type=""]', self.NAMESPACES)
        doc_id = first_ref_entry.attrib["Id"]

        doc_props = self._get_node("xades:SignedDataObjectProperties")
        first_doc_entry = doc_props.find('.//xades:DataObjectFormat[@ObjectReference="#%s"]' % doc_id, self.NAMESPACES)

        if self.doc_ids:
            next_num = len(self.doc_ids) + 1

            # generate new Id attribute
            while True:
                new_doc_id = "r-id-{}".format(next_num)
                if new_doc_id not in self.doc_ids:
                    break
                next_num += 1

            # Instead of manually creating elements, just copy the structure
            new_ref_entry = copy.deepcopy(first_ref_entry)
            signed_info.append(new_ref_entry)

            new_doc_entry = copy.deepcopy(first_doc_entry)
            doc_props.append(new_doc_entry)
        else:
            new_doc_id = doc_id.format(DOCUMENT_NUMBER=1)
            new_doc_entry = first_doc_entry
            new_ref_entry = first_ref_entry

        self.doc_ids.append(new_doc_id)
        new_ref_entry.attrib["Id"] = new_doc_id
        new_ref_entry.attrib["URI"] = file_name
        new_ref_entry.find(".//ds:DigestMethod", self.NAMESPACES).attrib["Algorithm"] = digest_algo
        new_ref_entry.find(".//ds:DigestValue", self.NAMESPACES).text = base64.b64encode(doc_hash)

        new_doc_entry.attrib["ObjectReference"] = "#%s" % new_doc_id
        new_doc_entry.find(".//xades:MimeType", self.NAMESPACES).text = mime_type

        return self

    def update_signed_info(self) -> "XmlSignature":
        """Calculate the digest over SignedProperties and embed it in SignedInfo"""

        # Set signing time
        time_node = self._get_signing_time_node()
        # Add a UTC timestamp. Can't use isoformat() as it adds +00:00 and microseconds
        #  which can break the parser elsewhere
        time_node.text = get_utc_time().strftime("%Y-%m-%dT%H:%M:%SZ")

        self._calc_signed_properties_hash(update=True)

        self._prepared = True
        return self

    @property
    def prepared(self) -> bool:
        if self._prepared is None:
            self._prepared = False
            if self.get_signing_time():
                old, new = self._calc_signed_properties_hash()
                if old == new:
                    self._prepared = True
        return self._prepared

    def signed_data(self) -> bytes:
        if not self.prepared:
            raise ValueError("The XML signature is not prepared")
        sign_info_node = self._get_node("ds:SignedInfo")
        return self.canonicalize(sign_info_node)

    def digest(self) -> bytes:
        signature_algo = self.get_signature_algorithm()
        hash_algo_name = signature_algo.split("-")[-1]
        hash_algo = getattr(hashlib, hash_algo_name)
        return hash_algo(self.signed_data()).digest()

    def verify(self) -> "XmlSignature":
        hash_algo = self.get_signature_algorithm().split("-")[-1]
        cert = self.get_certificate_value()
        signature = self.get_signature_value()
        signed_data = self.signed_data()
        verify(cert, signature, signed_data, hash_algo)
        return self

    def get_signature_value(self):
        sig_value_node = self._get_signature_value_node()
        try:
            text = sig_value_node.text.strip()
        except AttributeError:
            return None

        return base64.b64decode(text) if text else None

    def set_signature_value(self, signature: bytes) -> "XmlSignature":
        """Insert the base64-encoded value of a signature obtained from a signing service or device

        NOTE: the signature method should be known in advance, as it's part of the SignedInfo structure over which
          the signature is calculated.

        :param signature: Binary signature
        """
        sig_value_node = self._get_signature_value_node()
        sig_value_node.text = base64.b64encode(signature)
        return self

    def get_signature_algorithm(self) -> str:
        """
        Returns the #hash part of the corresponding node, in form of 'rsa-sha256'

        This algorithm is expected to be present in SIGNATURE_ALGORITHMS and be in form of
        {CRYPTOMETHOD}-{DIGESTMETHOD}. See the note for `set_signature_algorithm` below.
        """
        sig_method_node = self._get_node("ds:SignatureMethod")
        return sig_method_node.attrib["Algorithm"].split("#")[-1]

    def set_signature_algorithm(self, algo: str = None) -> "XmlSignature":
        """Set a signature algorithm, if it is not the default one (rsa-sha256).

        NOTE: Since the algorithm is included in the signed data, it is not possible to change the algo
        after signing.

        Ultimately, if an external signing service MAY select different algos at its discretion,
        this field should be ignored.

        FWIW the verification method of this class only takes into account
        the hash algo (DIGESTMETHOD) part of this attribute.

        :param algo: signature algorithm, one of SIGNATURE_ALGORITHMS
        """
        if algo:
            algo = algo.lower()
            if algo not in self.SIGNATURE_ALGORITHMS:
                raise ValueError("Unsupported signature algorithm")
        else:
            algo = self.SIGNATURE_ALGORITHMS[0]
        sig_method_node = self._get_node("ds:SignatureMethod")
        sig_method_node.attrib["Algorithm"] = self.SIGNATURE_ALGO_ID_TEMPLATE.format(algo=algo)
        return self

    def set_root_ca_cert(self, root_cert: Union[Certificate, bytes]) -> "XmlSignature":
        """Sets a root CA cert. This is not mandatory

        :param root_cert: can be a PEM- or DER-encoded bytes content, or an `oscrypto.Certificate` object
        """
        self.add_cert(root_cert, {"Id": f"{self.NEW_SIGNATURE_ID}-ROOT-CA-CERT"})
        return self

    def add_cert(self, cert: Union[Certificate, bytes], attribs: Optional[Dict] = None) -> "XmlSignature":
        """Add a cert. Latvian EDOC must have all of certs used in the xml (Root, OCSP and TimeStamp)
           This is mandatory for Latvian EDOC format

        :param cert: can be a PEM- or DER-encoded bytes content, or an `oscrypto.Certificate` object
        :param attrib: dict with attributes for <EncapsulatedX509Certificate> tag
        """
        certs_node = self._get_node("xades:CertificateValues")
        ca_node = etree.Element("{%s}EncapsulatedX509Certificate" % self.NAMESPACES["xades"])

        if attribs is not None:
            for name, value in attribs.items():
                ca_node.attrib[name] = value

        if not isinstance(cert, Certificate):
            cert = load_certificate(cert)
        ca_node.text = base64.b64encode(cert.asn1.dump())
        certs_node.append(ca_node)
        return self

    def set_ocsp_response(self, ocsp_response: OCSP, embed_ocsp_certificate=False) -> "XmlSignature":
        """
        Embed the OCSP response and certificates

        :param OCSP ocsp_response:
        :param bool embed_ocsp_certificate: Whether to add ocsp certificate to the xml.
            This is needed when the OCSP service in use
            does not embed the certificate in its response.
        :return: self
        """
        ocsp_response_node = self._get_node("xades:EncapsulatedOCSPValue")
        ocsp_response_node.text = base64.b64encode(ocsp_response.get_encapsulated_response())

        if embed_ocsp_certificate:
            ocsp_certs_node = self._get_node("xades:CertificateValues")
            ocsp_certs = ocsp_response.get_responder_certs()
            cert_node = ocsp_certs_node.find(".//xades:EncapsulatedX509Certificate", namespaces=self.NAMESPACES)
            cert_node.text = base64.b64encode(ocsp_certs[0].dump())
            cert_node.attrib["Id"] = "S1-Responder-cert-1"

            for i, next_cert in enumerate(ocsp_certs[1:]):
                cert_node = copy.deepcopy(cert_node)
                cert_node.text = base64.b64encode(ocsp_certs[next_cert].dump())
                cert_node.attrib["Id"] = "S1-Responder-cert-%d" % i
                ocsp_certs_node.append(cert_node)

        return self

    def get_ocsp_response(self) -> Optional[OCSP]:
        ocsp_response_node = self._get_node("xades:EncapsulatedOCSPValue")
        try:
            text = ocsp_response_node.text.strip()
        except AttributeError:
            return None

        return OCSP.load(base64.b64decode(text)) if text else None

    def verify_ocsp_response(self) -> "XmlSignature":
        """Verify embedded OCSP response.

        :raises exceptions.SignatureVerificationError:
        """
        try:
            self.get_ocsp_response().verify()
        except AttributeError:
            raise SignatureVerificationError("The XML Signature doesn't contain an OCSP response")
        return self

    def verify_ts_response(self) -> "XmlSignature":
        """Verify embedded TSA response.

        :raises exceptions.SignatureVerificationError:
        """
        TSA.verify(self.get_timestamp_response(), self.get_timestamped_message())
        return self

    def get_timestamped_message(self) -> bytes:
        sig_value_node = self._get_signature_value_node()
        method = self.get_c14n_method("xades:SignatureTimeStamp")
        return self.canonicalize(sig_value_node, method)

    def get_timestamp_response(self) -> Optional[bytes]:
        """
        Get the embedded TSA response for an LT-TS profile signature.

        LT-TM must not even have the XML node.
        """
        ts_value_node = self._get_node("xades:EncapsulatedTimeStamp")
        try:
            text = ts_value_node.text.strip()
        except AttributeError:
            return None
        return base64.b64decode(text) if text else None

    def set_timestamp_response(self, tsr) -> "XmlSignature":
        ts_value_node = self._get_node("xades:EncapsulatedTimeStamp")
        ts_value_node.text = base64.b64encode(tsr.dump())
        return self

    def remove_timestamp_node(self) -> "XmlSignature":
        """LT-TM profile requires the absence of the XML node"""
        ts_value_node = self._get_node("xades:SignatureTimeStamp")
        ts_value_node.getparent().remove(ts_value_node)
        return self

    def get_c14n_method(self, parent_node="ds:SignedInfo"):
        """Get a c14n method used within a specific context given by `parent_node`

        The default context is the SignedInfo node. Also encountered in SignatureTimestamp
        """
        method_node = self._get_node("{}/ds:CanonicalizationMethod".format(parent_node))
        if method_node is not None:
            method = method_node.attrib["Algorithm"]
            if method not in self.C14N_METHODS:
                raise ValueError("Unknown c14n method: {}".format(method))
        else:
            method = self.C14N_METHODS[0]
        return method

    def canonicalize(self, node, method=None) -> bytes:
        if method is not None:
            assert method in self.C14N_METHODS
        else:
            method = self.get_c14n_method()
        exclusive = "xml-exc-c14n" in method
        return etree.tostring(node, method="c14n", exclusive=exclusive)

    def _get_node(self, tag_name) -> etree._Element:
        return self.xml.find(".//{}".format(tag_name), namespaces=self.NAMESPACES)

    def _get_signed_properties_node(self):
        return self.xml.find(
            "./ds:Signature/ds:Object/xades:QualifyingProperties/xades:SignedProperties", self.NAMESPACES
        )

    def _get_signing_time_node(self):
        return self.xml.find(
            "./ds:Signature/ds:Object/xades:QualifyingProperties/xades:SignedProperties/"
            "xades:SignedSignatureProperties/xades:SigningTime",
            self.NAMESPACES,
        )

    def _get_signed_info_ref_node(self):
        """Find the SignedInfo/Reference node that refers to the XMLSig itself (not to the signed files)"""
        return next(
            self.xml.find('./ds:Signature/ds:SignedInfo/ds:Reference[@Type="%s"]' % ref_type, self.NAMESPACES)
            for ref_type in self.SIGNED_PROPERTIES_TYPE
        )

    def _get_signed_properties_c14n_algo(self, signed_info_ref_node: etree._Element):
        """
        Gets a transform/c14n algorithm for SignedProperties

        The child nodes may be absent, in this case use the default c14n algo

        # This is very obscure in the standard:
        # https://www.w3.org/TR/2002/REC-xmldsig-core-20020212/#sec-ReferenceProcessingModel
        """
        try:
            c14n_algo = signed_info_ref_node.find("./ds:Transforms/ds:Transform", self.NAMESPACES).attrib["Algorithm"]
        except:  # noqa: E722
            c14n_algo = None
        return c14n_algo

    def _get_signature_value_node(self):
        return self.xml.find("./ds:Signature/ds:SignatureValue", self.NAMESPACES)

    def _calc_signed_properties_hash(self, update=False) -> tuple:
        """
        Calculates, and updates, if requested, the SignedInfo/Reference/DigestValue

        ...based on the current SignedProperties

        :param update: update the digest value with current SignedProperties hash
        :return: tuple(DigestValue node value, SignedProperties hash value)
        """
        si_ref_node = self._get_signed_info_ref_node()

        signed_props_node = self._get_signed_properties_node()
        c14n_algo = self._get_signed_properties_c14n_algo(si_ref_node)

        signed_props_c14n = self.canonicalize(signed_props_node, c14n_algo)
        # TODO select algorithm based on DigestMethod // update DigestMethod
        signed_props_hash = hashlib.sha256(signed_props_c14n).digest()

        new_digest_value = base64.b64encode(signed_props_hash).decode()

        si_digest_node = si_ref_node.find("./ds:DigestValue", self.NAMESPACES)
        if update:
            si_digest_node.text = new_digest_value

        return si_digest_node.text, new_digest_value
