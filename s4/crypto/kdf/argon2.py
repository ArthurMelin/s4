import base64
from ctypes import *

from ..libcrypto import OSSL_PARAM, OSSL_PARAM_UNSIGNED_INTEGER, OSSL_PARAM_OCTET_STRING, random_bytes
from .base import KDF


class _Argon2(KDF):
    def __init__(self, params: dict[str, str] | None):
        self.__salt = None
        self.__t = 4
        self.__m = 128*1024
        self.__p = 64

        if params is not None:
            if (s := params.get("s", None)) is not None:
                self.__salt = base64.b64decode(s)
            if (p := params.get("p", None)) is not None:
                p = int(p)
                if not (1 <= p <= 2**24-1):
                    raise ValueError("p must be between 1 and 2^24-1")
                self.__p = p
            if (m := params.get("m", None)) is not None:
                m = int(m)
                if not (8*self.__p <= m <= 2**32-1):
                    raise ValueError("m must be between 8p and 2^32-1")
                self.__m = m
            if (t := params.get("t", None)) is not None:
                t = int(t)
                if not (1 <= t <= 2**32-1):
                    raise ValueError("t must be between 1 and 2^32-1")
                self.__t = t

        if self.__salt is None:
            self.__salt = random_bytes(16)

        t = c_uint32(self.__t)
        m = c_uint32(self.__m)
        p = c_uint32(self.__p)

        ossl_params = (OSSL_PARAM * 5)()
        ossl_params[0] = OSSL_PARAM(b"salt", OSSL_PARAM_OCTET_STRING, cast(self.__salt, c_void_p), len(self.__salt), 0)
        ossl_params[1] = OSSL_PARAM(b"iter", OSSL_PARAM_UNSIGNED_INTEGER, addressof(t), sizeof(t), 0)
        ossl_params[2] = OSSL_PARAM(b"memcost", OSSL_PARAM_UNSIGNED_INTEGER, addressof(m), sizeof(m), 0)
        ossl_params[3] = OSSL_PARAM(b"lanes", OSSL_PARAM_UNSIGNED_INTEGER, addressof(p), sizeof(p), 0)

        super()._init(ossl_params)

    @property
    def params(self) -> dict[str, str]:
        return {
            "s": base64.b64encode(self.__salt).decode(),
            "t": str(self.__t),
            "m": str(self.__m),
            "p": str(self.__p),
        }


class Argon2D(_Argon2):
    _name = b"ARGON2D"


class Argon2I(_Argon2):
    _name = b"ARGON2I"


class Argon2ID(_Argon2):
    _name = b"ARGON2ID"
