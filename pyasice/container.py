import io
import os
import re
from typing import BinaryIO, Optional, Union
from zipfile import BadZipFile, ZIP_DEFLATED, ZIP_STORED, ZipFile

from lxml import etree
from oscrypto.asymmetric import Certificate

from .exceptions import ContainerError, NoFilesToSign
from .xmlsig import XmlSignature


class Container(object):
    """
    Manipulate ASiC-E/BDoc v2 containers.

    Create a new container:

        bdoc = Container()
        bdoc\
            .add_file('test.pdf', b'Test data', 'application/pdf')\
            .add_signature(xmlsig)\
            .save('test.bdoc')

    Use `name` to open an existing container:

        bdoc = Container('test.bdoc')
        bdoc.verify_signatures()
        with bdoc.open_file('test.pdf') as f:
            assert f.read() == b'Test data'

        another_xmlsig = XmlSignature.create()...
        bdoc.add_signature(another_xmlsig).save()

    Spec: https://www.id.ee/public/bdoc-spec212-eng.pdf [1]
    """

    # save an `import ...` for users of the class
    Error = ContainerError
    NoFilesToSign = NoFilesToSign

    META_DIR = "META-INF"
    # > The names of these files shall contain the string "signatures" [1], ch.8
    SIGNATURE_FILES_REGEX = r"^%s/signatures(\d+)\.xml$" % META_DIR
    SIGNATURE_FILES_TEMPLATE = "%s/signatures{}.xml" % META_DIR

    # Manifest structure constants
    MANIFEST_FILE = "manifest.xml"
    MANIFEST_PATH = "{}/{}".format(META_DIR, MANIFEST_FILE)
    MANIFEST_NS = "urn:oasis:names:tc:opendocument:xmlns:manifest:1.0"
    MANIFEST_NAMESPACES = {
        "manifest": MANIFEST_NS,
    }
    MANIFEST_TAG_FILE_ENTRY = "{%s}file-entry" % MANIFEST_NS
    MANIFEST_ATTR_MEDIA_TYPE = "{%s}media-type" % MANIFEST_NS
    MANIFEST_ATTR_FULL_PATH = "{%s}full-path" % MANIFEST_NS

    MANIFEST_TEMPLATE_FILE = os.path.join(os.path.dirname(__file__), "templates", "manifest.xml")
    MIME_TYPE = "application/vnd.etsi.asic-e+zip"
    MIME_TYPE_FILE = "mimetype"

    def __init__(self, stream: Optional[BinaryIO] = None):
        """
        Create or open a BDOC/ASiC-E container from a stream, like a file handle or a BytesIO buffer.

        NOTE: if `stream` is not empty, opening an existing container is attempted.

        :param stream: a BytesIO buffer, or an open file
        """

        self._zip_file: Optional[ZipFile] = None
        self._zip_buffer: io.BytesIO

        if stream is None:
            self._zip_buffer = self._create_container()

            # adding manifest can be deferred to the save() method call
            self._manifest = None
            self._manifest_write_required = True
        else:
            if isinstance(stream, io.BytesIO):
                buffer = stream
                buffer.seek(0)
            elif hasattr(stream, "read") and callable(stream.read):
                # Treat name_or_file as an open file handle
                buffer = io.BytesIO(stream.read())
            else:
                raise TypeError(f"Failed to open stream {type(stream)}")

            self._zip_buffer = buffer

            self.verify_container()
            self._manifest_write_required = False

    @classmethod
    def open(cls, path: str):
        with open(path, "rb") as f:
            return cls(f)

    def prepare_signature(self, signer_certificate: Union[bytes, Certificate]):
        """Generates an XML signature structure for files in the container"""
        if not self.has_data_files():
            raise NoFilesToSign(f"Container `{self}` contains no files to sign")

        # Generate a XAdES signature
        xml_sig = XmlSignature.create()

        for file_name, content, mime_type in self.iter_data_files():
            xml_sig.add_document(file_name, content, mime_type)

        xml_sig.set_certificate(signer_certificate).update_signed_info()

        return xml_sig

    def finalize(self) -> io.BytesIO:
        """Finalizes the zip archive and returns the BytesIO buffer.

        This allows passing the existing io.BytesIO handle without copying the data.

        **NOTE:** After this method call, the container becomes unusable. Otherwise,
          the buffer might be modified, which kind of defeats the optimization.
        """
        self._write_manifest()
        buffer = self._zip_buffer
        buffer.seek(0)
        self._close()
        return buffer

    def save(self, path: str):
        """Save the BDoc file to FS. This also closes the Container."""
        with open(path, "wb") as f:
            f.write(self.finalize().getbuffer())

    def add_file(self, file_name: str, binary_data: bytes, mime_type="application/octet-stream", compress=True):
        """Add a data file.

        :param file_name: the name of the file in the Zip archive
        :param binary_data: the content of the file
        :param mime_type: the file's content type as it appears in the container's manifest
        :param compress: on by default, there is no reason not to compress (except special cases)
        """
        manifest_xml = self._get_manifest_xml()
        new_manifest_entry = etree.Element(self.MANIFEST_TAG_FILE_ENTRY)
        new_manifest_entry.attrib[self.MANIFEST_ATTR_MEDIA_TYPE] = mime_type
        new_manifest_entry.attrib[self.MANIFEST_ATTR_FULL_PATH] = file_name
        manifest_xml.append(new_manifest_entry)
        compress_type = ZIP_DEFLATED if compress else ZIP_STORED
        with self.zip_writer as zip_file:
            zip_file.writestr(file_name, binary_data, compress_type)
        self._manifest_write_required = True
        return self

    @property
    def zip_file(self):
        """
        Returns a read only ZipFile handle for the current buffer.
        """
        if not self._zip_file:
            if self._zip_buffer is None:
                raise self.Error("Failed to read zip file: the container is closed")

            try:
                self._zip_file = ZipFile(self._zip_buffer, "r")
            except BadZipFile as e:
                raise self.Error("Failed to open container: not a valid zip file") from e
        return self._zip_file

    @property
    def zip_writer(self):
        """
        Returns a writable (append-mode) ZipFile handle.
        """
        if self._zip_buffer is None:
            raise self.Error("Failed to modify zip file: the container is closed")
        # clear the cached zip reader
        self._close_zip_file()
        return ZipFile(self._zip_buffer, "a")

    @property
    def data_file_names(self):
        return [name for name, _ in self._enumerate_data_files()]

    @property
    def signature_file_names(self):
        return self._enumerate_signatures()

    def has_data_files(self):
        return any(self._enumerate_data_files())  # False if no elements

    def iter_data_files(self):
        """
        Iterate over 3-tuples of file name, content and mime_type
        """
        for file_name, mime_type in self._enumerate_data_files():
            with self.open_file(file_name) as f:
                yield file_name, f.read(), mime_type

    def open_file(self, file_name):
        """Read a file contained in the container"""
        return self.zip_file.open(file_name)

    def add_signature(self, signature: XmlSignature):
        """Add a signature calculated over the data files."""
        embedded_signatures = sorted(self._enumerate_signatures())

        if embedded_signatures:
            last_n = re.match(self.SIGNATURE_FILES_REGEX, embedded_signatures[-1]).group(1)
            next_n = int(last_n) + 1  # even with alphabetic file sorting, this gives valid next number
        else:
            next_n = 1

        new_sig_file = self.SIGNATURE_FILES_TEMPLATE.format(next_n)
        assert new_sig_file not in embedded_signatures
        with self.zip_writer as zip_file:
            zip_file.writestr(new_sig_file, signature.dump(), ZIP_DEFLATED)
        return self

    def iter_signatures(self):
        """Iterate over embedded signatures"""
        for entry in self._enumerate_signatures():
            with self.open_file(entry) as f:
                yield XmlSignature(f.read())

    def verify_signatures(self):
        """Verify all signatures in the container

        :raises signature_verifier.SignatureVerificationError:
        """
        for xmlsig in self.iter_signatures():
            xmlsig.verify()
        return self

    def verify_container(self):
        failed = self.zip_file.testzip()
        if failed:
            raise self.Error("The container contains errors. First broken file: %s" % failed)

        toc = self.zip_file.namelist()
        if not toc:
            raise self.Error(f"Empty container '{self}'")
        if toc[0] != self.MIME_TYPE_FILE:
            # Check that mimetype is the first entry.
            # NOTE: actually as per ETSI TS 102 918, MIME_TYPE_FILE is optional
            # neither is it explicitly stated as *the first entry* in BDOC2.1:2014 [OID: 1.3.6.1.4.1.10015.1000.3.2.3]
            # but digidoc software deems the opposite.
            raise self.Error(f"Container '{self}' must contain mime type file '{self.MIME_TYPE_FILE}' as first file")
        if self.MANIFEST_PATH not in toc:
            raise self.Error(f"Container '{self}' does not contain manifest file '{self.MANIFEST_FILE}'")

        # Read the meta data
        with self.open_file(self.MIME_TYPE_FILE) as f:
            mime_type = f.read()
        if mime_type.decode() != self.MIME_TYPE:
            raise self.Error(f"Invalid mime type '{mime_type}' for container '{self}'")

        try:
            with self.open_file(self.MANIFEST_PATH) as f:
                self._manifest = etree.XML(f.read())
        except Exception as e:
            raise self.Error(f"Failed to read manifest for container '{self}'") from e

        toc_data_files = [
            file_name
            for file_name in toc[1:]  # the first one is MIME_TYPE_FILE, can be skipped
            if not file_name.startswith(self.META_DIR)
        ]

        manifest_data_files = [name for name, _ in self._enumerate_data_files()]

        if sorted(toc_data_files) != sorted(manifest_data_files):
            raise self.Error("Manifest file is out of date")

    def _write_manifest(self):
        """Create/update the manifest"""
        if not self._manifest_write_required:
            return

        manifest_xml = self._get_manifest_xml()

        if self.MANIFEST_PATH in self._read_toc():
            self._delete_files(self.MANIFEST_PATH)

        with self.zip_writer as zip_file:
            zip_file.writestr(
                self.MANIFEST_PATH, b'<?xml version="1.0" encoding="UTF-8"?>' + etree.tostring(manifest_xml)
            )

    @classmethod
    def _create_container(cls):
        buffer = io.BytesIO()
        with ZipFile(buffer, "w") as new_zip_file:
            # NOTE: the mimetype entry should be the first one in the zip file and not compressed,
            # as per ETSI TS 102 918 (though optional)
            new_zip_file.writestr(cls.MIME_TYPE_FILE, cls.MIME_TYPE.encode(), ZIP_STORED)
        return buffer

    def _read_toc(self):
        """Read table of contents"""
        return self.zip_file.namelist()

    def _get_manifest_xml(self):
        if self._manifest is None:
            # Create a manifest from template
            with open(self.MANIFEST_TEMPLATE_FILE, "rb") as f:
                self._manifest = etree.XML(f.read())
        return self._manifest

    def _enumerate_signatures(self):
        return [file_name for file_name in self._read_toc() if re.match(self.SIGNATURE_FILES_REGEX, file_name)]

    def _delete_files(self, *file_names_to_delete):
        new_buf = io.BytesIO()
        new_zip_file = ZipFile(new_buf, "w")
        file_names_to_delete = set(file_names_to_delete)
        for entry in self._zip_file.infolist():
            file_name = entry.filename
            if file_name in file_names_to_delete:
                file_names_to_delete.remove(file_name)
                continue

            with self.open_file(file_name) as f:
                new_zip_file.writestr(file_name, f.read(), entry.compress_type)

        new_zip_file.close()
        self._close_zip_file()  # clear the cached zip reader
        self._zip_buffer = new_buf

    def _enumerate_data_files(self):
        """
        Yields 2-tuples of file name and mime_type
        """
        manifest_xml = self._get_manifest_xml()
        media_type_attr = self.MANIFEST_ATTR_MEDIA_TYPE
        full_path_attr = self.MANIFEST_ATTR_FULL_PATH

        for file_entry in manifest_xml.iterchildren():
            assert file_entry.tag == self.MANIFEST_TAG_FILE_ENTRY
            file_name = file_entry.attrib[full_path_attr]
            if file_name != "/":  # skip the 'root' entry
                yield file_name, file_entry.attrib[media_type_attr]

    def _close_zip_file(self):
        if self._zip_file:
            self._zip_file.close()
            self._zip_file = None

    def _close(self):
        self._close_zip_file()
        self._zip_buffer = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._close()

    def __str__(self):
        return repr(self)
