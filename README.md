# pyasice - ASiC-E (BDOC) and XAdES Manipulation Library

The `pyasice` library is designed to:
* create, read, and verify XAdES/XMLDsig/eIDAS electronic signatures,
* validate signers' certificates,
* confirm these signatures with TimeStamping, 
* create and manipulate [ASiC-E](https://en.wikipedia.org/wiki/Associated_Signature_Containers) or BDoc 2.1 containers, 
which are based on the XAdES/eIDAS stack.  

## Contents

* [Normative References](#normative-references)
* [Module Layout](#module-layout)
* [Technology Stack](#technology-stack)
* [Build the XAdES XML Signature meta-file](#build-the-xades-xml-signature-meta-file)
* * [SignedInfo](#signedinfo)
* * [SignatureValue](#signaturevalue)
* * [KeyInfo](#keyinfo)
* * [SignedProperties](#signedproperties)
* [Secondary Services](#secondary-services)
* * [OCSP](#ocsp)
* * [Timestamping Service](#timestamping-service)
* [ASiC-E/BDOC Container File Manipulation](#asic-ebdoc-container-file-manipulation)

## Normative References

The main document this library is based on:
the [BDOC 2.1.2 spec](https://www.id.ee/wp-content/uploads/2020/06/bdoc-spec212-eng.pdf).

The specific standards outlined in that document:

* [ETSI TS 101 903 v1.4.2](https://www.etsi.org/deliver/etsi_ts/101900_101999/101903/01.04.02_60/ts_101903v010402p.pdf) 
  – XML Advanced Electronic Signatures (XAdES) and its Baseline Profile ETSI TS 103 171;
* ITU-T Recommendation X.509;
* [RFC 3161](https://tools.ietf.org/html/rfc3161) – PKIX Time-Stamp protocol;
* [RFC 6960](https://tools.ietf.org/html/rfc6960) – Online Certificate Status Protocol;
* ETSI TS 102 918 v1.2.1 - Associated Signature Containers (ASiC) and its
  Baseline Profile ETSI TS 103 174.

The difference between ASiC-E and BDOC is almost exclusively in the terminology use.

The [BDOC 2.1.2 spec](https://www.id.ee/wp-content/uploads/2020/06/bdoc-spec212-eng.pdf) states:

> The BDOC file format is based on ASiC standard which is in turn profiled by ASiC BP.
> BDOC packaging is a ASiC-E XAdES type ZIP container ...

So with a moderate risk of confusion, we can accept that ASiC-E and BDOC refer to the same thing.

## Module Layout

* [container.py](container.py) -- the `Container` class, that deals with ASiC-E (BDOC v.2.1) container format 
* [xmlsig.py](xmlsig.py) -- the `XmlSignature` class, that deals with XAdES/XMLDSig XML structures
* [ocsp.py](ocsp.py) -- the `OCSP` class that deals with OCSP requests and responses
* [tsa.py](tsa.py) -- the `TSA` class that deals with TimeStamping service requests and responses
* [signature_verifier.py](signature_verifier.py) -- the `verify` function, to verify signatures against a certificate.

## Technology Stack

Dealing with the subject involves, at least:
* public key cryptography (RSA, ECDSA);
* ASN.1 encoding;
* XML processing;
* Zip archives;
* and also requests to various services (obtaining signer's certificate and the signature,
  validating the certificate through OCSP, time-stamping the signature).

The [asn1crypto](https://github.com/wbond/asn1crypto) library and its higher-level complement 
[oscrypto](https://github.com/wbond/oscrypto)
allow handling certificates and ASN.1 structures quite easily.

The [cryptography](https://cryptography.io/en/latest) library is by far the most powerful python library 
for dealing with public key cryptography algorithms.


## Build the XAdES XML Signature meta-file

The structure of the XAdES XML signature file looks like this:
```xml
<asic:XAdESSignatures xmlns:asic="http://uri.etsi.org/02918/v1.2.1#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
                      xmlns:xades="http://uri.etsi.org/01903/v1.3.2#">
    <ds:Signature Id="S0">
        <ds:SignedInfo Id="S0-SignedInfo">...</ds:SignedInfo>
        <ds:SignatureValue Id="S0-SIG">...</ds:SignatureValue>
        <ds:KeyInfo Id="S0-KeyInfo">...</ds:KeyInfo>
        <ds:Object Id="S0-object-xades">
            <xades:QualifyingProperties Id="S0-QualifyingProperties" Target="#S0">
                <xades:SignedProperties Id="S0-SignedProperties">
                    <xades:SignedSignatureProperties Id="S0-SignedSignatureProperties">
                        <xades:SigningTime>2019-06-07T14:03:50Z</xades:SigningTime>
                        <xades:SigningCertificate>...</xades:SigningCertificate>
                        <xades:SignaturePolicyIdentifer>...</xades:SignaturePolicyIdentifer>
                    </xades:SignedSignatureProperties>
                </xades:SignedProperties>
            </xades:QualifyingProperties>
        </ds:Object>
    </ds:Signature>
</asic:XAdESSignatures>
```

We'll go over each section below.

* [SignedInfo](#signedinfo)
* [SignatureValue](#signaturevalue)
* [KeyInfo](#keyinfo)
* [SignedProperties](#signedproperties)

### SignedInfo

```xml
<ds:SignedInfo Id="S0-SignedInfo">
    <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2006/12/xml-c14n11"></ds:CanonicalizationMethod>
    <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"></ds:SignatureMethod>
    <ds:Reference Id="S0-ref-0" URI="test.pdf">
        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"></ds:DigestMethod>
        <ds:DigestValue>...</ds:DigestValue>
    </ds:Reference>
    <ds:Reference Id="S0-ref-sp" Type="http://uri.etsi.org/01903#SignedProperties" URI="#S0-SignedProperties">
        <ds:Transforms>
            <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
        </ds:Transforms>
        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"></ds:DigestMethod>
        <ds:DigestValue>...</ds:DigestValue>
    </ds:Reference>
</ds:SignedInfo>
```

This section contains some static fields, like `CanonicalizationMethod` and `SignatureMethod`. 
The `CanonicalizationMethod` tag defines an algorithm used for XML canonicalization, more on that below in this chapter.

The other, most important, fields are the `Reference` ones. And they are quite different in purpose and formation.

The first `Reference` field is about the signed document and as such, has an `URI` attribute of the document's file name.
Its child `DigestValue` element is the SHA256 hash of the document, it is, incidentally, the very hash that is sent to the SmartID API for signing.

The second `Reference` is an interesting beast, as it is built on the basis of some fields defined later in the [SignedProperties](#SignedProperties) section.
Its child `DigestValue` is calculated as a SHA256 hash of the canonicalized XML output of the  `SignedProperties` tag, after that one is formed:
The `URI` attribute of this `Reference` tag is the `#`-prefixed `Id` attribute of the `SignedProperties` tag.

```python
import base64
import hashlib
from lxml import etree

buf = etree.tostring(el, method='c14n', exclusive=True or False)  # NOTE below
digest_value = base64.b64encode(hashlib.sha256(buf).digest())
```
(Assuming the `el` here to be the XML `<SignedProperties>` element)

#### Canonicalization

The `exclusive` kwarg controls whether the namespace declarations of ancestor tags should be included in the resulting canonical representation, or _excluded_.
Whether to use `exclusive=True` depends on the canonicalization tag's `Algorithm` attribute: 
* `http://www.w3.org/2001/10/xml-exc-c14n#`, uses `exclusive=True`,  
* the two others, the required `http://www.w3.org/TR/2001/REC-xml-c14n-20010315`, or `http://www.w3.org/2006/12/xml-c14n11`, are not exclusive.

The aforementioned `<ds:CanonicalizationMethod>` tag controls the c14n of the `SignedInfo` node before feeding its digest to the signature service. 
The c14n of `SignedProperties` prior to getting its digest is determined by the `ds:Transform` tag within this `ds:Reference` node. 
If it's not present, then the default, ie. not exclusive, c14n is used.  

### KeyInfo

This section contains just the base64-encoded user certificate value, e.g. the SmartID API response's `cert.value`:
```xml
<ds:KeyInfo Id="S0-KeyInfo">
    <ds:X509Data>
        <ds:X509Certificate>MIIGJDCCBAygAwIBAgIQBNsLtTIpnmNbbE4+laSLaTANBgkqhkiG9w0BAQsFADBr...</ds:X509Certificate>
    </ds:X509Data>
</ds:KeyInfo>
```
More details about the certificate in the [SigningCertificate](#SigningCertificate) subsection.
 
### SignedProperties

The XML section of `SignedProperties` consists of, at least :question:, the `SigningTime`, `SigningCertificate` and `SignaturePolicyIdentifer` elements.

#### SigningTime

Is a timestamp in ISO 8601 format.

#### SignaturePolicyIdentifier 

This appears to be a static^1 XML chunk referencing the BDOC 2.1 Specifications document:
```xml
<xades:SignaturePolicyIdentifier>
    <xades:SignaturePolicyId>
        <xades:SigPolicyId>
            <xades:Identifier Qualifier="OIDAsURN">urn:oid:1.3.6.1.4.1.10015.1000.3.2.1</xades:Identifier>
        </xades:SigPolicyId>
        <xades:SigPolicyHash>
            <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256">
            </ds:DigestMethod>
            <ds:DigestValue>3Tl1oILSvOAWomdI9VeWV6IA/32eSXRUri9kPEz1IVs=</ds:DigestValue>
        </xades:SigPolicyHash>
        <xades:SigPolicyQualifiers>
            <xades:SigPolicyQualifier>
                <xades:SPURI>https://www.sk.ee/repository/bdoc-spec21.pdf</xades:SPURI>
            </xades:SigPolicyQualifier>
        </xades:SigPolicyQualifiers>
    </xades:SignaturePolicyId>
</xades:SignaturePolicyIdentifier>
```

[1] The DigestValue is the hash value of current document in base64 encoding. Refer to [BDOC 2.1:2014 Specification](https://www.id.ee/public/bdoc-spec212-eng.pdf) for more information.

#### SigningCertificate

The user certificate is a base64-encoded DER certificate which can be loaded as follows:
```python
import base64
from cryptography import x509
from cryptography.hazmat.backends import default_backend
cert_asn1 = base64.b64decode(cert_value)
cert = x509.load_der_x509_certificate(base64.b64decode(cert_asn1), default_backend())
```
or with `pyopenssl`:
```python
import base64
from OpenSSL.crypto import load_certificate, FILETYPE_ASN1
cert_asn1 = base64.b64decode(cert_value)
openssl_cert = load_certificate(FILETYPE_ASN1, base64.b64decode(cert_asn1))
```
These objects expose a slightly different but similar API.

What we need is the issuer name and certificate serial number:
```python
assert openssl_cert.get_serial_number() == cert.sertial_number == '6454262457486410408874311107672836969'
assert cert.issuer.rfc4514_string() == 'C=EE,O=AS Sertifitseerimiskeskus,2.5.4.97=NTREE-10747013,CN=TEST of ESTEID-SK 2015'
assert openssl_cert.issuer.get_components() == [(b'C', b'EE'), (b'O', b'AS Sertifitseerimiskeskus'), (b'organizationIdentifier', b'NTREE-10747013'), (b'CN', b'ESTEID-SK 2015')]  
```

Also we need a SHA256 digest value of the certificate:
```python
cert_digest = base64.b64encode(hashlib.sha256(cert_asn1).digest())
```

With these values we can build the certificate information entry of the SignedProperties:
```xml
<xades:SigningCertificate>
    <xades:Cert>
        <xades:CertDigest>
            <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"></ds:DigestMethod>
            <ds:DigestValue>hdsLTm4aaFKaGMwF6fvH5vWmiMBBnTCH3kba+TjY+pE=</ds:DigestValue>
        </xades:CertDigest>
        <xades:IssuerSerial>
            <ds:X509IssuerName>C=EE,O=AS Sertifitseerimiskeskus,2.5.4.97=NTREE-10747013,CN=TEST of EID-SK 2016</ds:X509IssuerName>
            <ds:X509SerialNumber>98652662091042892833248946646759285960</ds:X509SerialNumber>
        </xades:IssuerSerial>
    </xades:Cert>
</xades:SigningCertificate>
```

:question: Does `X509IssuerName` content need to be a `cert.issuer.rfc4514_string()` or can it be anything else?

So, in the end, we get a `<xades:SignedProperties>` element which we then canonicalize and calculate a sha256 hash of this string,
to place it in the appropriate `<ds:Reference>` element.

### SignatureValue

This is the `signature.value` from the SmartID response.

:question: Is it?

### KeyInfo

Contains the base64-encoded certificate, as gotten from the SmartID response.
```xml
<ds:KeyInfo Id="S0-KeyInfo">
    <ds:X509Data>
        <ds:X509Certificate>...</ds:X509Certificate>
    </ds:X509Data>
</ds:KeyInfo>
```

## Secondary Services

### OCSP

OCSP ([Online Certificate Status Protocol](https://en.wikipedia.org/wiki/Online_Certificate_Status_Protocol)) 
is designed to check that the signing certificate is valid at the point of signing. It is a binary protocol, and uses ASN.1 encoding in both request and response payload.
To deal with it, we're using the `asn1crypto` library.

The OCSP request should be made immediately after signing, and the base64-encoded response is embedded in the XAdES signature as a `xades:UnsignedSignatureProperties` descendant node,
namely `xades:EncapsulatedOCSPValue`.

#### Estonian eID

URLs for OCSP services:
* Demo: `http://demo.sk.ee/ocsp`
* Production: `http://ocsp.sk.ee/`

More detail on the [sk.ee OCSP page](https://www.sk.ee/en/services/validity-confirmation-services/technical-information/)


### Timestamping service

The [TimeStamp protocol](https://en.wikipedia.org/wiki/Time_stamp_protocol) is also a binary protocol, for getting a Long-Term Validity Timestamp for a signature. 
Also handled with the help of the `asn1crypto` library.

The TSA request should be made immediately after OCSP validity confirmation, and the base64-encoded response is embedded in the XAdES signature as a `xades:UnsignedSignatureProperties` descendant node,
namely `xades:EncapsulatedTimeStamp`.

#### Estonian eID

URLs for timestamping services:
* Demo: `http://demo.sk.ee/tsa/`
* Production: `http://tsa.sk.ee`

More detail on the [sk.ee TSA page](https://www.sk.ee/en/services/time-stamping-service/)


## ASiC-E/BDOC Container File Manipulation

Create a new container:
```python
from pyasice import Container, XmlSignature

xmlsig = XmlSignature.create().add_document('test.txt', b'Test data', 'application/pdf')
# ... here goes the signing, confirming and timestamping part ... 

container = Container()
container\
    .add_file('test.txt', b'Test data', 'application/pdf')\
    .add_signature(xmlsig)\
    .save('test.asice')
```

Use `Container(filename)` to open an existing container:
```python
from pyasice import Container, XmlSignature

container = Container('test.asice')

# Verify container
container.verify_signatures()

# Read files in the container
with container.open_file('test.txt') as f:
    assert f.read() == b'Test data'

# Add signatures
another_xmlsig = XmlSignature.create().add_document('name', b'content', 'mime/type')
# ... here goes the signing, confirming and timestamping part ... 
container.add_signature(another_xmlsig).save()
```
