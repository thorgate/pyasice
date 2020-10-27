class PyAsiceError(Exception):
    """
    A generic exception that can happen while dealing with ASic-E/BDoc 2 files/signatures
    """

    pass


class ContainerError(PyAsiceError):
    pass


class NoFilesToSign(PyAsiceError):
    pass


class SignatureVerificationError(PyAsiceError):
    pass


class InvalidSignatureAlgorithm(SignatureVerificationError):
    pass
