from .base import AEAD, Cipher


class AES128CBC(Cipher):
    _name = b"AES-128-CBC"
class AES192CBC(Cipher):
    _name = b"AES-192-CBC"
class AES256CBC(Cipher):
    _name = b"AES-256-CBC"

class AES128CTR(Cipher):
    _name = b"AES-128-CTR"
class AES192CTR(Cipher):
    _name = b"AES-192-CTR"
class AES256CTR(Cipher):
    _name = b"AES-256-CTR"

class AES128GCM(AEAD):
    _name = b"AES-128-GCM"
class AES192GCM(AEAD):
    _name = b"AES-192-GCM"
class AES256GCM(AEAD):
    _name = b"AES-256-GCM"
