from abc import ABC, abstractmethod
from ctypes import *

from ..libcrypto import _import, OpenSSLError, OSSL_PARAM, OSSL_PARAM_OCTET_STRING
from ..smart_ptr import smart_ptr


class EVP_KDF_p(c_void_p): pass
class EVP_KDF_CTX_p(c_void_p): pass

EVP_KDF_fetch = _import("EVP_KDF_fetch", EVP_KDF_p, c_void_p, c_char_p, c_char_p)
EVP_KDF_free = _import("EVP_KDF_free", None, EVP_KDF_p)
EVP_KDF_CTX_new = _import("EVP_KDF_CTX_new", EVP_KDF_CTX_p, EVP_KDF_p)
EVP_KDF_CTX_free = _import("EVP_KDF_CTX_free", None, EVP_KDF_CTX_p)
EVP_KDF_CTX_get_kdf_size = _import("EVP_KDF_CTX_get_kdf_size", c_size_t, EVP_KDF_CTX_p)
EVP_KDF_CTX_set_params = _import("EVP_KDF_CTX_set_params", c_int, EVP_KDF_CTX_p, POINTER(OSSL_PARAM))
EVP_KDF_CTX_derive = _import("EVP_KDF_derive", c_int, EVP_KDF_CTX_p, c_void_p, c_size_t, POINTER(OSSL_PARAM))


class KDF(ABC):
    _name: bytes = NotImplemented

    @classmethod
    def __get_kdf(cls):
        if not hasattr(cls, "_KDF__kdf"):
            kdf = EVP_KDF_fetch(None, cls._name, None)
            if not kdf:
                raise ValueError("unknown cipher")
            cls.__kdf = smart_ptr[EVP_KDF_p](kdf, EVP_KDF_free)
        return cls.__kdf.value

    def __init__(self, params: dict[str, str] | None) -> None:
        raise TypeError("__init__ should not be called on base class")

    def _init(self, params: Array[OSSL_PARAM]) -> None:
        self._ctx = smart_ptr[EVP_KDF_CTX_p](EVP_KDF_CTX_new(self.__get_kdf()), EVP_KDF_CTX_free)
        if not self._ctx:
            raise OpenSSLError("EVP_KDF_CTX_new")

        if EVP_KDF_CTX_set_params(self._ctx.value, params) <= 0:
            raise OpenSSLError("EVP_KDF_CTX_set_params")

    def derive(self, password: bytes, outlen: int | None = None) -> bytes:
        outlen_alg = EVP_KDF_CTX_get_kdf_size(self._ctx.value)
        if outlen_alg == c_size_t(-1).value:
            if outlen is None:
                raise TypeError(f"outlen is required because kdf has variable output size")
        else:
            if outlen is None:
                outlen = outlen_alg
            elif outlen != outlen_alg:
                raise ValueError(f"kdf has fixed output size of {outlen_alg}")
        params = (OSSL_PARAM * 2)()
        params[0] = OSSL_PARAM(b"pass", OSSL_PARAM_OCTET_STRING, cast(password, c_void_p), len(password), 0)
        buf = create_string_buffer(outlen)
        if EVP_KDF_CTX_derive(self._ctx.value, buf, outlen, params) <= 0:
            raise OpenSSLError("EVP_KDF_derive")
        return buf.raw

    @property
    @abstractmethod
    def params(self) -> dict[str, str]:
        pass
