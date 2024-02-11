import sys

if sys.version_info < (3, 12):
    print("s4 requires python 3.12+", file=sys.stderr)
    exit(1)


from .crypto import libcrypto

if libcrypto.version < (3, 2, 0):
    current = ".".join(str(n) for n in libcrypto.version)
    print(f"s4 requires OpenSSL 3.2.0+ (loaded: {current})", file=sys.stderr)
    exit(1)
