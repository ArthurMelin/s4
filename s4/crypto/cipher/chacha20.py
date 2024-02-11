from .base import Cipher, AEAD


class ChaCha20(Cipher):
    _name = b"ChaCha20"

    @classmethod
    def get_iv_len(cls):
        return 8

    def __init__(self, enc: bool, key: bytes, iv: bytes) -> None:
        if len(iv) != self.get_iv_len():
            raise ValueError("invalid nonce length")
        iv =  b"\0" * 8 + iv
        super().__init__(enc, key, iv)


class ChaCha20Poly1305(AEAD):
    _name = b"ChaCha20-Poly1305"

    # OpenSSL's implementation of chacha20-poly1305 is based on the RFC 7539 which uses a 32 bits counter, but it
    # currently increments the counter as 64 bits. We can then reserve the first 4 bytes of IV to be used as the rest of
    # the initial counter value (zeroes) instead.
    @classmethod
    def get_iv_len(cls):
        return 8

    def __init__(self, enc: bool, key: bytes, iv: bytes, auth_tag_len: int = 16) -> None:
        if len(iv) != self.get_iv_len():
            raise ValueError("invalid nonce length")
        iv = b"\0" * 4 + iv
        super().__init__(enc, key, iv, auth_tag_len)
