import base64
from ctypes import *

from ..libcrypto import OSSL_PARAM, OSSL_PARAM_UNSIGNED_INTEGER, OSSL_PARAM_OCTET_STRING, random_bytes
from .base import KDF


class Scrypt(KDF):
    _name = b"SCRYPT"

    def __init__(self, params: dict[str, str] | None):
        self.__salt = None
        self.__N = 2048
        self.__r = 8
        self.__p = 64

        if params is not None:
            if (s := params.get("s", None)) is not None:
                self.__salt = base64.b64decode(s)
            if (r := params.get("r", None)) is not None:
                r = int(r)
                if r < 1:
                    raise ValueError("r must be positive")
                self.__r = r
            if (n := params.get("n", None)) is not None:
                n = int(n)
                if n & (n - 1) != 0:
                    raise ValueError("N must be a power of two")
                if not (1 < n < 2**(128*self.__r/8)):
                    raise ValueError("N must be larger than 1 and less than 2^(128r/8)")
                self.__N = n
            if (p := params.get("p", None)) is not None:
                p = int(p)
                if not (1 <= p <= (2**32-1) * 32 / (128*self.__r)):
                    raise ValueError("p must be between 1 and (2^32-1) * 32 / (128r)")
                self.__p = p

        if self.__salt is None:
            self.__salt = random_bytes(16)

        n = c_uint64(self.__N)
        r = c_uint32(self.__r)
        p = c_uint32(self.__p)

        ossl_params = (OSSL_PARAM * 5)()
        ossl_params[0] = OSSL_PARAM(b"salt", OSSL_PARAM_OCTET_STRING, cast(self.__salt, c_void_p), len(self.__salt), 0)
        ossl_params[1] = OSSL_PARAM(b"n", OSSL_PARAM_UNSIGNED_INTEGER, addressof(n), sizeof(n), 0)
        ossl_params[2] = OSSL_PARAM(b"r", OSSL_PARAM_UNSIGNED_INTEGER, addressof(r), sizeof(r), 0)
        ossl_params[3] = OSSL_PARAM(b"p", OSSL_PARAM_UNSIGNED_INTEGER, addressof(p), sizeof(p), 0)

        super()._init(ossl_params)

    @property
    def params(self) -> dict[str, str]:
        return {
            "s": base64.b64encode(self.__salt).decode(),
            "n": str(self.__N),
            "r": str(self.__r),
            "p": str(self.__p),
        }
