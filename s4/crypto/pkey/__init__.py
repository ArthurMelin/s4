from .base import UserKey, UserKeyDH, UserKeyRawKey

from .x25519 import X25519
from .x448 import X448


__all__ = [
    "UserKey",
    "UserKeyDH",
    "UserKeyRawKey",
    "algorithms",

    "X25519",
    "X448",
]

algorithms: dict[str, type[UserKey]] = {
    "x25519": X25519,
    "x448": X448,
}
