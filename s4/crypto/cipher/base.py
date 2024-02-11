from abc import ABC, abstractmethod
from ctypes import *

from ..libcrypto import _import, OpenSSLError, OSSL_PARAM, OSSL_PARAM_OCTET_STRING
from ..smart_ptr import smart_ptr


class EVP_CIPHER_p(c_void_p): pass
class EVP_CIPHER_CTX_p(c_void_p): pass

EVP_CIPHER_fetch = _import("EVP_CIPHER_fetch", EVP_CIPHER_p, c_void_p, c_char_p, c_char_p)
EVP_CIPHER_free = _import("EVP_CIPHER_free", None, EVP_CIPHER_p)
EVP_CIPHER_get_block_size = _import("EVP_CIPHER_get_block_size", c_int, EVP_CIPHER_p)
EVP_CIPHER_get_key_length = _import("EVP_CIPHER_get_key_length", c_int, EVP_CIPHER_p)
EVP_CIPHER_get_iv_length = _import("EVP_CIPHER_get_iv_length", c_int, EVP_CIPHER_p)
EVP_CIPHER_CTX_new = _import("EVP_CIPHER_CTX_new", EVP_CIPHER_CTX_p)
EVP_CIPHER_CTX_free = _import("EVP_CIPHER_CTX_free", None, EVP_CIPHER_CTX_p)
EVP_CIPHER_CTX_get_params = _import("EVP_CIPHER_CTX_get_params", c_int, EVP_CIPHER_CTX_p, POINTER(OSSL_PARAM))
EVP_CIPHER_CTX_set_params = _import("EVP_CIPHER_CTX_set_params", c_int, EVP_CIPHER_CTX_p, POINTER(OSSL_PARAM))
EVP_CIPHER_CTX_set_key_length = _import("EVP_CIPHER_CTX_set_key_length", c_int, EVP_CIPHER_CTX_p, c_int)
EVP_CIPHER_CTX_set_padding = _import("EVP_CIPHER_CTX_set_padding", c_int, EVP_CIPHER_CTX_p, c_int)
EVP_CipherInit_ex2 = _import("EVP_CipherInit_ex2", c_int, EVP_CIPHER_CTX_p, EVP_CIPHER_p, c_void_p, c_void_p, c_int, POINTER(OSSL_PARAM))
EVP_CipherUpdate = _import("EVP_CipherUpdate", c_int, EVP_CIPHER_CTX_p, c_void_p, POINTER(c_int), c_void_p, c_int)
EVP_CipherFinal_ex = _import("EVP_CipherFinal_ex", c_int, EVP_CIPHER_CTX_p, c_void_p, POINTER(c_int))


class Cipher(ABC):
    _name: bytes = NotImplemented

    @classmethod
    def __get_cipher(cls):
        if not hasattr(cls, "_Cipher__cipher"):
            cipher = EVP_CIPHER_fetch(None, cls._name, None)
            if not cipher:
                raise ValueError("unknown cipher")
            cls.__cipher = smart_ptr[EVP_CIPHER_p](cipher, EVP_CIPHER_free)
        return cls.__cipher.value

    @classmethod
    def get_key_len(cls):
        return EVP_CIPHER_get_key_length(cls.__get_cipher())

    @classmethod
    def get_iv_len(cls):
        return EVP_CIPHER_get_iv_length(cls.__get_cipher())

    def __init__(self, enc: bool, key: bytes, iv: bytes | None) -> None:
        self._enc = enc
        self.__buffer = None

        self._ctx = smart_ptr[EVP_CIPHER_CTX_p](EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free)
        if not self._ctx:
            raise OpenSSLError("EVP_CIPHER_CTX_new")

        if EVP_CipherInit_ex2(self._ctx.value, self.__get_cipher(), None, None, enc, None) <= 0:
            raise OpenSSLError("failed to initialize cipher")

        if EVP_CIPHER_CTX_set_key_length(self._ctx.value, len(key)) <= 0:
            raise ValueError("invalid key length")

        expected_iv_len = EVP_CIPHER_get_iv_length(self.__get_cipher())
        if (not iv and expected_iv_len > 0) or (iv and len(iv) != expected_iv_len):
            raise ValueError(f"invalid iv length, expected {expected_iv_len} bytes, got {len(iv) if iv else None}")

        if EVP_CipherInit_ex2(self._ctx.value, self.__get_cipher(), key, iv, enc, None) <= 0:
            raise OpenSSLError("failed to initialize cipher")

    def __get_buffer(self, size: int) -> Array[c_char]:
        buf = self.__buffer
        if not buf or len(buf) < size:
            buf = create_string_buffer(size)
            self.__buffer = buf
        return buf

    def set_auto_padding(self, enable: bool) -> None:
        if EVP_CIPHER_CTX_set_padding(self._ctx.value, int(enable)) <= 0:
            raise OpenSSLError("EVP_CIPHER_CTX_set_padding")

    def update(self, data: bytes) -> bytes:
        buf = self.__get_buffer(len(data))
        outlen = c_int()
        if EVP_CipherUpdate(self._ctx.value, buf, byref(outlen), data, len(data)) <= 0:
            raise OpenSSLError("EVP_CipherUpdate")
        return buf.raw[:outlen.value]

    def final(self) -> bytes:
        buf = self.__get_buffer(EVP_CIPHER_get_block_size(self.__cipher.value))
        outlen = c_int()
        if EVP_CipherFinal_ex(self._ctx.value, buf, byref(outlen)) <= 0:
            raise OpenSSLError("EVP_CipherFinal_ex")
        return buf.raw[:outlen.value]


class AEAD(Cipher):
    def __init__(self, enc: bool, key: bytes, iv: bytes | None, auth_tag_len: int = 16):
        super().__init__(enc, key, iv)
        self.__auth_tag_len = auth_tag_len
        # TODO set variable auth tag len
        # TODO handle setting custom AEAD ivlen

    def get_auth_tag_len(self):
        return self.__auth_tag_len

    def set_aad(self, aad: bytes):
        outlen = c_int()
        if EVP_CipherUpdate(self._ctx.value, None, byref(outlen), aad, len(aad)) <= 0:
            raise OpenSSLError("EVP_CipherUpdate")

    def get_auth_tag(self) -> bytes:
        if not self._enc:
            raise TypeError("cannot get auth tag when decrypting")
        tag = create_string_buffer(self.__auth_tag_len)
        params = (OSSL_PARAM * 2)()
        params[0] = OSSL_PARAM(b"tag", OSSL_PARAM_OCTET_STRING, cast(tag, c_void_p), self.__auth_tag_len, 0)
        if EVP_CIPHER_CTX_get_params(self._ctx.value, params) <= 0:
            raise OpenSSLError("EVP_CIPHER_CTX_get_params")
        return tag.raw

    def set_auth_tag(self, tag: bytes):
        if self._enc:
            raise TypeError("cannot set auth tag when encrypting")
        params = (OSSL_PARAM * 2)()
        params[0] = OSSL_PARAM(b"tag", OSSL_PARAM_OCTET_STRING, cast(tag, c_void_p), len(tag), 0)
        if EVP_CIPHER_CTX_set_params(self._ctx.value, params) <= 0:
            raise OpenSSLError("EVP_CIPHER_CTX_set_params")
