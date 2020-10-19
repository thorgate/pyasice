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
        request = TimeStampReq(
            {
                "version": "v1",
                "message_imprint": {
                    "hash_algorithm": {"algorithm": "sha256"},
                    "hashed_message": hashlib.sha256(message).digest(),
                },
                "cert_req": True,  # Need the TSA cert in the response for validation
            }
        )

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

        assert response.status_code == 200
        assert response.headers["Content-Type"] == self.RESPONSE_CONTENT_TYPE

        ts_response = TimeStampResp.load(response.content)
        assert ts_response["status"]["status_string"][0].native == "Operation Okay"

        self.ts_response = ts_response
        return ts_response["time_stamp_token"]

    @classmethod
    def verify(cls, ts_response: bytes):
        """
        Verify that the signature in the response is valid.

        https://tools.ietf.org/html/rfc5652#section-5.4
        """
        try:
            ts_response = ContentInfo.load(ts_response)
            content = ts_response['content']

            # the encapsulated TS message ("econtent")
            econtent = content['encap_content_info']['content'].contents
            digest_algo = content['digest_algorithms'][0]['algorithm'].native
            econtent_digest = getattr(hashlib, digest_algo)(econtent).digest()

            signer_info = content['signer_infos'][0]

            # if signed_attrs are absent, the signed data is a hash of the econtent itself
            try:
                # asn1 primitive types have no `.get()` method
                signed_attrs = signer_info['signed_attrs']
            except KeyError:
                signed_attrs = None

            if signed_attrs is not None:
                # Verify that "econtent" hash matches the message_digest attribute of signed_attrs

                # get the hash
                md = [a for a in signed_attrs.native if a['type'] == 'message_digest'][0]
                the_hash = md['values'][0]
                if econtent_digest != the_hash:
                    raise ValueError("Message digests do not match")

                # Do the magic described in the RFC 5652 (the link in docstring) as:
                #    the DER encoding of the EXPLICIT SET OF tag, rather than of the IMPLICIT [0]
                #    tag, MUST be included in the message digest calculation
                # i.e. replace the current (class, tag) pair with those of the SET-OF type
                signed_attrs.implicit = False
                signed_attrs.class_ = SetOf.class_
                signed_attrs.tag = SetOf.tag
                signed_data = signed_attrs.dump(True)

            else:
                signed_data = econtent_digest

            # Verify the signature with the included cert
            cert = content['certificates'][0].chosen

            signature = signer_info['signature']
            assert isinstance(signature, OctetString)
            signature_bytes = signature.native

            sig_algo = signer_info['signature_algorithm']['algorithm'].native
            sig_hash_algo = sig_algo.split('_')[0]

            verify(cert.dump(), signature_bytes, signed_data, sig_hash_algo)

        except Exception as e:
            raise TSAError("Invalid TSA response format") from e
        return ts_response
