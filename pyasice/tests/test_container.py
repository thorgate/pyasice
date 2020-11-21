import io
import os
from tempfile import NamedTemporaryFile

import pytest

from oscrypto.asymmetric import load_certificate

from pyasice import Container, XmlSignature


@pytest.fixture
def temporary_file():
    f = NamedTemporaryFile(delete=False)

    yield f.name

    os.unlink(f.name)


def test_container_init__from_file(signed_container_file):
    bdoc_file = Container(signed_container_file)
    assert bdoc_file.data_file_names


def test_container_init__from_bytes_io(signed_container_file):
    bdoc_file = Container(io.BytesIO(signed_container_file.read()))
    assert bdoc_file.data_file_names


def test_container_init__from_empty(signed_container_file):
    with pytest.raises(Container.Error, match="not a valid zip file"):
        Container(io.BytesIO())


def test_container_init__from_non_readable(signed_container_file):
    with pytest.raises(TypeError, match="Failed to open stream"):
        Container("text")


def test_bdoc_open_save(temporary_file):
    with Container() as bdoc_file:
        bdoc_file.save(temporary_file)

    with pytest.raises(Container.Error) as e:
        bdoc_file.add_file("test.txt", b"this is a test", "text/plain")
        assert e.match("container is closed")

    with pytest.raises(Container.Error):
        bdoc_file.open_file("test.txt")
        assert e.match("container is closed")

    with Container.open(temporary_file) as bdoc_file:
        bdoc_file.add_file("test.txt", b"this is a test", "text/plain")
        assert bdoc_file.data_file_names == ["test.txt"]

    with pytest.raises(Container.Error):
        bdoc_file.open_file("test.txt")
        assert e.match("container is closed")


def test_bdoc_data_files(temporary_file):
    with Container() as bdoc_file:
        assert list(bdoc_file.iter_data_files()) == []

        bdoc_file.add_file("test.txt", b"this is a test", "text/plain")
        bdoc_file.save(temporary_file)

    bdoc_file = Container.open(temporary_file)
    assert list(bdoc_file.iter_data_files()) == [("test.txt", b"this is a test", "text/plain")]

    bdoc_file.add_file("test2.txt", b"another test", "text/plain")
    assert bdoc_file.data_file_names == ["test.txt", "test2.txt"]

    bdoc_file.save(temporary_file)

    bdoc_file = Container.open(temporary_file)
    assert bdoc_file.data_file_names == ["test.txt", "test2.txt"]

    assert list(bdoc_file.iter_data_files()) == [
        ("test.txt", b"this is a test", "text/plain"),
        ("test2.txt", b"another test", "text/plain"),
    ]

    with bdoc_file.open_file("test.txt") as f:
        assert f.read() == b"this is a test"

    with bdoc_file.open_file("test2.txt") as f:
        assert f.read() == b"another test"


def test_bdoc_data_files_unicode(temporary_file):
    filename = "test-АБВГДЕЖЗ-ÄÜÕÖ£€.txt"
    bdoc_file = Container()
    bdoc_file.add_file(filename, b"test", "text/plain")

    assert bdoc_file.data_file_names == [filename]
    assert list(bdoc_file.iter_data_files()) == [(filename, b"test", "text/plain")]

    bdoc_file.save(temporary_file)
    bdoc_file = Container.open(temporary_file)
    assert bdoc_file.data_file_names == [filename]


def test_bdoc_signatures(temporary_file):
    bdoc_file = Container()
    bdoc_file.add_file("test.txt", b"this is a test", "text/plain")

    assert list(bdoc_file.iter_signatures()) == []

    xml_sig = XmlSignature.create().set_signature_value(b"signature")
    bdoc_file.add_signature(xml_sig)

    assert bdoc_file.signature_file_names == ["META-INF/signatures1.xml"]
    assert [sig.get_signature_value() for sig in bdoc_file.iter_signatures()] == [b"signature"]

    bdoc_file.save(temporary_file)

    # Open anew
    bdoc_file = Container.open(temporary_file)
    assert bdoc_file.signature_file_names == ["META-INF/signatures1.xml"]
    assert [sig.get_signature_value() for sig in bdoc_file.iter_signatures()] == [b"signature"]

    xml_sig = XmlSignature.create().set_signature_value(b"signature2")
    bdoc_file.add_signature(xml_sig).save(temporary_file)

    bdoc_file = Container.open(temporary_file)
    assert bdoc_file._enumerate_signatures() == ["META-INF/signatures1.xml", "META-INF/signatures2.xml"]
    assert [sig.get_signature_value() for sig in bdoc_file.iter_signatures()] == [b"signature", b"signature2"]


def test_bdoc_signature_numbers():
    bdoc_file = Container()
    bdoc_file.add_file("test.txt", b"this is a test", "text/plain")
    bdoc_file.zip_writer.writestr("META-INF/signatures111.xml", b"dummy")
    xml_sig = XmlSignature.create().set_signature_value(b"signature")
    bdoc_file.add_signature(xml_sig)

    assert bdoc_file.signature_file_names == ["META-INF/signatures111.xml", "META-INF/signatures112.xml"]


def test_bdoc_finalize(temporary_file, xml_signature_rsa_signed):
    with Container() as bdoc_file:
        bdoc_file.add_file("test.txt", b"this is a test", "text/plain")
        buffer = bdoc_file.add_signature(xml_signature_rsa_signed).finalize()

    bdoc_file2 = Container(buffer)

    assert bdoc_file2.signature_file_names == ["META-INF/signatures1.xml"]
    assert bdoc_file2.data_file_names == ["test.txt"]

    bdoc_file2.verify_signatures()
    assert "No exception was raised"


@pytest.mark.parametrize("cert_type", ["bytes", "oscrypto.Certificate"])
def test_bdoc_prepare_signature(certificate_rsa_bytes, cert_type):
    bdoc_file = Container()

    if cert_type == "bytes":
        certificate = certificate_rsa_bytes
    else:
        certificate = load_certificate(certificate_rsa_bytes)

    with pytest.raises(Container.NoFilesToSign):
        bdoc_file.prepare_signature(certificate)

    bdoc_file.add_file("test.txt", b"test", "text.plain")
    result = bdoc_file.prepare_signature(certificate)
    assert isinstance(result, XmlSignature)

    assert result.get_certificate_value() == certificate_rsa_bytes
