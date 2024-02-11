from ctypes import *
import ctypes.util


libcrypto = CDLL(ctypes.util.find_library("crypto"))

def _import(symbol: str, restype: type | None, *argtypes: type):
    f = libcrypto[symbol]
    f.argtypes = argtypes
    f.restype = restype
    return f

# Params

class OSSL_PARAM(Structure):
    _fields_ = [
        ("key", c_char_p),
        ("data_type", c_uint8),
        ("data", c_void_p),
        ("data_size", c_size_t),
        ("return_size", c_size_t),
    ]

OSSL_PARAM_INTEGER = 1
OSSL_PARAM_UNSIGNED_INTEGER = 2
OSSL_PARAM_REAL = 3
OSSL_PARAM_UTF8_STRING = 4
OSSL_PARAM_OCTET_STRING = 5
OSSL_PARAM_UTF8_PTR = 6
OSSL_PARAM_OCTET_PTR = 7

OSSL_PARAM_free = _import("OSSL_PARAM_free", None, POINTER(OSSL_PARAM))

# RNG

RAND_bytes = _import("RAND_bytes", c_int, c_void_p, c_int)

def random_bytes(num: int) -> bytes:
    buf = create_string_buffer(num)
    if RAND_bytes(buf, num) != 1:
        raise OpenSSLError("RAND_bytes")
    return buf.raw

# Misc

OPENSSL_version_major = _import("OPENSSL_version_major", c_uint)
OPENSSL_version_minor = _import("OPENSSL_version_minor", c_uint)
OPENSSL_version_patch = _import("OPENSSL_version_patch", c_uint)

version = (
    OPENSSL_version_major(),
    OPENSSL_version_minor(),
    OPENSSL_version_patch(),
)

# Error handling

ERR_get_error = _import("ERR_get_error", c_ulong)
ERR_error_string = _import("ERR_error_string", c_char_p, c_ulong, c_char_p)

class OpenSSLError(RuntimeError):
    def __init__(self, msg: str):
        try:
            errcode = ERR_get_error()
            errbuf = create_string_buffer(256)
            errmsg = ERR_error_string(errcode, errbuf)
            errmsg = errmsg.decode("utf-8")
            msg = f"{msg}: {errmsg}"
        except:
            pass
        super().__init__(msg)
