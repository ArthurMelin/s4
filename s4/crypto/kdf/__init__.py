from .base import KDF

from .argon2 import Argon2D, Argon2I, Argon2ID
from .scrypt import Scrypt


__all__ = [
    "KDF",
    "algorithms",

    "Argon2D",
    "Argon2I",
    "Argon2ID",
    "Scrypt",
]

algorithms: dict[str, type[KDF]] = {
    "argon2d": Argon2D,
    "argon2i": Argon2I,
    "argon2id": Argon2ID,
    "scrypt": Scrypt,
}
