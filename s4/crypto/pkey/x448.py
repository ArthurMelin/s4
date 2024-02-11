from .base import UserKey, UserKeyDH, UserKeyRawKey


class X448(UserKeyDH, UserKeyRawKey, UserKey):
    _name = b"X448"

    @classmethod
    def raw_key_length(cls): return 56
