import hashlib
from abc import ABC, abstractmethod
from base64 import b64decode, b64encode
from ctypes import *

from ..libcrypto import _import, OpenSSLError, OSSL_PARAM
from ..smart_ptr import smart_ptr


class EVP_PKEY_p(c_void_p): pass
class EVP_PKEY_CTX_p(c_void_p): pass

EVP_PKEY_new_raw_private_key_ex = _import("EVP_PKEY_new_raw_private_key_ex", EVP_PKEY_p, c_void_p, c_char_p, c_char_p, c_void_p, c_size_t)
EVP_PKEY_new_raw_public_key_ex = _import("EVP_PKEY_new_raw_public_key_ex", EVP_PKEY_p, c_void_p, c_char_p, c_char_p, c_void_p, c_size_t)
EVP_PKEY_get_raw_public_key = _import("EVP_PKEY_get_raw_public_key", c_int, EVP_PKEY_p, c_char_p, POINTER(c_size_t))
EVP_PKEY_free = _import("EVP_PKEY_free", None, EVP_PKEY_p)
EVP_PKEY_check = _import("EVP_PKEY_check", c_int, EVP_PKEY_CTX_p)
EVP_PKEY_derive_init_ex = _import("EVP_PKEY_derive_init_ex", c_int, EVP_PKEY_CTX_p, POINTER(OSSL_PARAM))
EVP_PKEY_derive_set_peer_ex = _import("EVP_PKEY_derive_set_peer_ex", c_int, EVP_PKEY_CTX_p, EVP_PKEY_p, c_int)
EVP_PKEY_derive = _import("EVP_PKEY_derive", c_int, EVP_PKEY_CTX_p, c_void_p, POINTER(c_size_t))
EVP_PKEY_keygen_init = _import("EVP_PKEY_keygen_init", c_int, EVP_PKEY_CTX_p)
EVP_PKEY_keygen = _import("EVP_PKEY_keygen", c_int, EVP_PKEY_CTX_p, POINTER(EVP_PKEY_p))
EVP_PKEY_CTX_new_from_name = _import("EVP_PKEY_CTX_new_from_name", EVP_PKEY_CTX_p, c_void_p, c_char_p, c_char_p)
EVP_PKEY_CTX_new_from_pkey = _import("EVP_PKEY_CTX_new_from_pkey", EVP_PKEY_CTX_p, c_void_p, EVP_PKEY_p, c_char_p)
EVP_PKEY_CTX_free = _import("EVP_PKEY_CTX_free", None, EVP_PKEY_CTX_p)


class UserKey(ABC):
    _name: bytes = NotImplemented

    def _init(self, data: bytes | None) -> None:
        if data is None:
            gen_ctx = smart_ptr[EVP_PKEY_CTX_p](EVP_PKEY_CTX_new_from_name(None, self._name, None), EVP_PKEY_CTX_free)
            if not gen_ctx:
                raise OpenSSLError("EVP_PKEY_CTX_new_from_name")
            if EVP_PKEY_keygen_init(gen_ctx.value) <= 0:
                raise OpenSSLError("EVP_PKEY_keygen_init")
            self._pkey = smart_ptr(EVP_PKEY_p(None), EVP_PKEY_free)
            if EVP_PKEY_keygen(gen_ctx.value, byref(self._pkey.value)) <= 0 or self._pkey.value is None:
                raise OpenSSLError("EVP_PKEY_keygen")
            del gen_ctx
        else:
            self._pkey = smart_ptr(self._load(data, private=True), EVP_PKEY_free)

        self._ctx = smart_ptr[EVP_PKEY_CTX_p](EVP_PKEY_CTX_new_from_pkey(None, self._pkey.value, None), EVP_PKEY_CTX_free)
        if not self._ctx:
            raise OpenSSLError("EVP_PKEY_CTX_new_from_pkey")

        if EVP_PKEY_check(self._ctx.value) <= 0:
            raise OpenSSLError("EVP_PKEY_check")

    def dump(self) -> bytes:
        return self._dump(self._pkey.value, private=True)

    @abstractmethod
    def fingerprint(self) -> str:
        pass

    @abstractmethod
    def wrap(self, data_key: bytes) -> str:
        pass

    @abstractmethod
    def unwrap(self, wrapped: str) -> bytes:
        pass

    @abstractmethod
    def _load(self, data: bytes, private: bool = False) -> EVP_PKEY_p:
        pass

    @abstractmethod
    def _dump(self, key: EVP_PKEY_p, private: bool = False) -> bytes:
        pass

class UserKeyDH(UserKey):
    def wrap(self, data_key: bytes) -> str:
        if EVP_PKEY_keygen_init(self._ctx.value) <= 0:
            raise OpenSSLError("EVP_PKEY_keygen_init")
        intermediate = smart_ptr(EVP_PKEY_p(None), EVP_PKEY_free)
        if EVP_PKEY_keygen(self._ctx.value, byref(intermediate.value)) <= 0 or intermediate.value is None:
            raise OpenSSLError("EVP_PKEY_keygen")
        secret = self.__diffie_hellman(intermediate.value)
        wrapping_key = hashlib.shake_256(secret).digest(len(data_key))
        wrapped_key = bytes(a ^ b for a, b in zip(data_key, wrapping_key))
        intermediate_data = self._dump(intermediate.value)
        return b64encode(wrapped_key).decode() + ":" + b64encode(intermediate_data).decode()

    def unwrap(self, wrapped: str) -> bytes:
        wrapped_key, intermediate_data = wrapped.split(":", 1)
        wrapped_key = b64decode(wrapped_key)
        intermediate_data = b64decode(intermediate_data)
        intermediate = smart_ptr[EVP_PKEY_p](self._load(intermediate_data), EVP_PKEY_free)
        secret = self.__diffie_hellman(intermediate.value)
        wrapping_key = hashlib.shake_256(secret).digest(len(wrapped_key))
        data_key = bytes(a ^ b for a, b in zip(wrapped_key, wrapping_key))
        return data_key

    def __diffie_hellman(self, remote: EVP_PKEY_p) -> bytes:
        if EVP_PKEY_derive_init_ex(self._ctx.value, None) <= 0:
            raise OpenSSLError("EVP_PKEY_CTX_derive_init_ex")
        if EVP_PKEY_derive_set_peer_ex(self._ctx.value, remote, 1) <= 0:
            raise OpenSSLError("EVP_PKEY_CTX_derive_set_peer_ex")
        outlen = c_size_t(0)
        if EVP_PKEY_derive(self._ctx.value, None, byref(outlen)) <= 0:
            raise OpenSSLError("EVP_PKEY_CTX_derive")
        out = create_string_buffer(outlen.value)
        if EVP_PKEY_derive(self._ctx.value, out, byref(outlen)) <= 0:
            raise OpenSSLError("EVP_PKEY_CTX_derive")
        return out.raw[:outlen.value]


class UserKeyRawKey(UserKey):
    @classmethod
    @abstractmethod
    def raw_key_length(cls) -> int:
        pass

    def __init__(self, data: bytes | None) -> None:
        if data is None:
            raise ValueError("raw keys should be loaded directly from KDF output")
        super()._init(data)

    def fingerprint(self) -> str:
        return self._dump(self._pkey.value, private=False).hex()

    def _load(self, raw: bytes, private: bool = False) -> EVP_PKEY_p:
        if len(raw) != self.raw_key_length():
            raise ValueError("invalid raw key length")
        pkey = (EVP_PKEY_new_raw_private_key_ex if private else EVP_PKEY_new_raw_public_key_ex)(None, self._name, None, raw, len(raw))
        if not pkey:
            raise ValueError("failed to load raw key")
        return pkey

    def _dump(self, pkey: EVP_PKEY_p, private: bool = False) -> bytes:
        if private:
            raise ValueError("raw keys should not be dumped")
        outlen = c_size_t(0)
        if EVP_PKEY_get_raw_public_key(pkey, None, byref(outlen)) <= 0:
            raise OpenSSLError("EVP_PKEY_get_raw_public_key")
        out = create_string_buffer(outlen.value)
        if EVP_PKEY_get_raw_public_key(pkey, out, byref(outlen)) <= 0:
            raise OpenSSLError("EVP_PKEY_get_raw_public_key")
        return out.raw[:outlen.value]


# EVP_PKEY_todata = _import("EVP_PKEY_todata", c_int, EVP_PKEY_p, c_int, POINTER(POINTER(OSSL_PARAM)))

# EVP_PKEY_KEY_PARAMETERS = 0x84
# EVP_PKEY_PRIVATE_KEY = 0x85
# EVP_PKEY_PUBLIC_KEY = 0x86
# EVP_PKEY_KEYPAIR = 0x87

# def _export_key_params(self, pkey: EVP_PKEY_p, private: bool = False) -> Dict[str, int | str | bytes]:
#     params = POINTER(OSSL_PARAM)()
#     if EVP_PKEY_todata(pkey, EVP_PKEY_KEYPAIR if private else EVP_PKEY_PUBLIC_KEY, byref(params)) <= 0:
#         raise OpenSSLError("EVP_PKEY_todata")
#     out = {}
#     i = 0
#     while params[i].key is not None:
#         p: OSSL_PARAM = params[i]
#         key: str = p.key.decode("utf-8")
#         dt: int = p.data_type
#         if dt not in (OSSL_PARAM_INTEGER, OSSL_PARAM_UNSIGNED_INTEGER, OSSL_PARAM_UTF8_STRING, OSSL_PARAM_OCTET_STRING):
#             raise NotImplementedError()
#         data: bytes = cast(p.data, POINTER(c_char * p.data_size)).contents.raw
#         if dt == OSSL_PARAM_INTEGER or dt == OSSL_PARAM_UNSIGNED_INTEGER:
#             value = int.from_bytes(data, byteorder=sys.byteorder, signed=(dt == OSSL_PARAM_INTEGER))
#         elif dt == OSSL_PARAM_UTF8_STRING:
#             value = data.decode("utf-8")
#         elif dt == OSSL_PARAM_OCTET_STRING:
#             value = data
#         out[key] = value
#         i += 1
#     OSSL_PARAM_free(params)
#     return out
