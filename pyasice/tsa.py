import hashlib

import requests
from asn1crypto.cms import ContentInfo  # noqa
from asn1crypto.core import OctetString, SetOf
from asn1crypto.tsp import TimeStampReq, TimeStampResp

from .exceptions import PyAsiceError
from .signature_verifier import verify


class TSAError(PyAsiceError):
    pass


class TSA:
    """
    Query a Time Stamping Authority (TSA) for a signature time stamp
    """

    REQUEST_CONTENT_TYPE = "application/timestamp-query"
    RESPONSE_CONTENT_TYPE = "application/timestamp-reply"

    def __init__(self, url):
        self.url = url
        self.ts_response = None

    def get_timestamp(self, message: bytes) -> ContentInfo:
        """Get the time stamp structure for embedding in a XAdES signature

        How to prepare the message:
        https://www.etsi.org/deliver/etsi_ts/101900_101999/101903/01.04.02_60/ts_101903v010402p.pdf
        section 7.3
        """
        request = self.build_ts_request(message)

        try:
            response = requests.post(
                self.url,
                data=request.dump(),
                headers={
                    "Content-Type": self.REQUEST_CONTENT_TYPE,
                    "Connection": "close",
                },
            )
            response.raise_for_status()
        except requests.ConnectionError as e:
            raise TSAError("Failed to connect to TSA service at {}".format(self.url)) from e
        except requests.HTTPError as e:
            raise TSAError("Bad response from TSA service at {}: {}".format(self.url, e)) from e

        content_type = response.headers["Content-Type"]
        if content_type != self.RESPONSE_CONTENT_TYPE:
            raise TSAError(f"Invalid response content type '{content_type}' returned by OCSP service at {self.url}")

        ts_response = TimeStampResp.load(response.content)
        # see asn1crypto.tsp.PKIStatus
        status = ts_response["status"]["status"].native
        if status != "granted":
            raise TSAError(f"Timestamping service denied the request with a status of {status}")

        self.ts_response = ts_response
        return ts_response["time_stamp_token"]

    @classmethod
    def verify(cls, ts_response: bytes, original_message: bytes):
        """
        Verify that the signature in the response is valid.

        https://tools.ietf.org/html/rfc5652#section-5.4
        """
        try:
            # any error during data structure parsing means the TS response is not valid
            ts_response = ContentInfo.load(ts_response)
            ts_content_type = ts_response.native["content_type"]

            # see asn1crypto.cms.ContentType
            if ts_content_type != "signed_data":
                raise ValueError(f"The TS response has invalid content type '{ts_content_type}'")

            content = ts_response["content"]

            # Get the encapsulated TS message ("econtent")
            econtent = content["encap_content_info"]["content"]

            # verify that the response refers to the original message

            message_imprint = econtent.native["message_imprint"]
            original_imprint = cls.build_message_imprint(original_message)
            if (
                message_imprint["hash_algorithm"]["algorithm"] != original_imprint["hash_algorithm"]["algorithm"]
                or message_imprint["hashed_message"] != original_imprint["hashed_message"]
            ):
                raise ValueError("The timestamped message differs from the original one")

            # Verify that "econtent" hash matches the message_digest attribute of signed_attrs

            digest_algo = content["digest_algorithms"][0]["algorithm"].native
            econtent_digest = getattr(hashlib, digest_algo)(econtent.contents).digest()

            signer_info = content["signer_infos"][0]

            signed_attrs = signer_info["signed_attrs"]

            md = [a for a in signed_attrs.native if a["type"] == "message_digest"][0]
            the_hash = md["values"][0]
            if econtent_digest != the_hash:
                raise ValueError("Message digests do not match")

            # Verify the signature with the included cert

            # To get signed data, we need some magic, as quoted from the RFC 5652 (the link in docstring):
            #    the DER encoding of the EXPLICIT SET OF tag, rather than of the IMPLICIT [0]
            #    tag, MUST be included in the message digest calculation
            # i.e. replace the current (class, tag) pair of the struct with those of the SET-OF type
            signed_attrs.implicit = False
            signed_attrs.class_ = SetOf.class_
            signed_attrs.tag = SetOf.tag
            signed_data = signed_attrs.dump(True)

            cert = content["certificates"][0].chosen

            signature: OctetString = signer_info["signature"]
            signature_bytes = signature.native

            sig_algo = signer_info["signature_algorithm"]["algorithm"].native
            sig_hash_algo = sig_algo.split("_")[0]

            verify(cert.dump(), signature_bytes, signed_data, sig_hash_algo)

        except Exception as e:
            raise TSAError("Invalid TSA response format") from e
        return ts_response

    @staticmethod
    def build_message_imprint(message):
        if not isinstance(message, bytes):
            raise TypeError(f"Invalid message type: expected bytes, got {type(message)}")
        if not message:
            raise ValueError("Message can not be empty")

        return {
            "hash_algorithm": {"algorithm": "sha256"},
            "hashed_message": hashlib.sha256(message).digest(),
        }

    @classmethod
    def build_ts_request(cls, message):
        return TimeStampReq(
            {
                "version": "v1",
                "message_imprint": cls.build_message_imprint(message),
                "cert_req": True,  # Need the TSA cert in the response for validation
            }
        )
