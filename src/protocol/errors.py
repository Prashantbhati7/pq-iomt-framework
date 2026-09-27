class ProtocolError(Exception):
    """Raised when a packet fails a protocol check (the paper's 'abort')."""


class MaliciousEdgeError(ProtocolError):
    """Device signature is valid but the HMAC is not: the QSES tampered with the packet."""