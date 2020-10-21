from .container import Container  # noqa: F401
from .exceptions import PyAsiceError, SignatureVerificationError  # noqa: F401
from .signature_verifier import verify  # noqa: F401
from .utils import finalize_signature  # noqa: F401
from .xmlsig import XmlSignature  # noqa: F401


# simply: except pyasice.Error
Error = PyAsiceError

__version__ = "1.0"
