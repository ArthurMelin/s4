from .base import AEAD, Cipher

from .aes import \
    AES128CBC, AES128CTR, AES128GCM, \
    AES192CBC, AES192CTR, AES192GCM, \
    AES256CBC, AES256CTR, AES256GCM
from .chacha20 import ChaCha20, ChaCha20Poly1305


__all__ = [
    "Cipher",
    "AEAD",
    "algorithms",

    "AES128CBC",
    "AES128CTR",
    "AES128GCM",
    "AES192CBC",
    "AES192CTR",
    "AES192GCM",
    "AES256CBC",
    "AES256CTR",
    "AES256GCM",
    "ChaCha20",
    "ChaCha20Poly1305",
]

algorithms: dict[str, type[Cipher]] = {
    "aes128cbc": AES128CBC,
    "aes128ctr": AES128CTR,
    "aes128gcm": AES128GCM,
    "aes192cbc": AES192CBC,
    "aes192ctr": AES192CTR,
    "aes192gcm": AES192GCM,
    "aes256cbc": AES256CBC,
    "aes256ctr": AES256CTR,
    "aes256gcm": AES256GCM,
    "chacha20": ChaCha20,
    "chacha20poly1305": ChaCha20Poly1305,
}
