class ProtocolError(Exception):
    """Raised when a packet fails a protocol check (the paper's 'abort')."""