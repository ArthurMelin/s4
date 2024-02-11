from .base import UserKey, UserKeyDH, UserKeyRawKey


class X25519(UserKeyDH, UserKeyRawKey, UserKey):
    _name = b"X25519"

    @classmethod
    def raw_key_length(cls): return 32
