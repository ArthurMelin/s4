import argparse
import getpass
import json
import sys
from typing import Any

from .. import crypto


help = "initialize bucket"

def parser(parser: argparse.ArgumentParser):
    parser.add_argument("--overwrite",
                        action="store_true",
                        help="overwrite existing S4 config")
    parser.add_argument("--yes-i-understand",
                        action="store_true",
                        help=argparse.SUPPRESS)
    parser.add_argument("--key-type",
                        choices=crypto.pkey.algorithms.keys(),
                        default="x448",
                        help="use specified user key type")
    parser.add_argument("--kdf-type",
                        choices=crypto.kdf.algorithms.keys(),
                        default="argon2id",
                        help="use specified KDF")
    parser.add_argument("--kdf-params",
                        type=json.loads,
                        help="use specified KDF params (JSON formatted)")
    parser.add_argument("--kok",
                        type=bytes.fromhex,
                        help="use specified key obfuscation key (32 bytes, in hex)")
    parser.add_argument("bucket",
                        metavar="BUCKET")


def run(args: argparse.Namespace, clients: dict[str, Any]):
    bucket = args.bucket

    if args.overwrite and not args.yes_i_understand:
        print(f"ANY PREVIOUSLY UPLOADED ENCRYPTED OBJECTS IN s4://{bucket} WILL BE LOST PERMANENTLY", file=sys.stderr)
        print("Use --yes-i-understand to confirm", file=sys.stderr)
        exit(1)

    password = getpass.getpass()
    if password != getpass.getpass("Confirm password: "):
        print("Password and confirmation don't match", file=sys.stderr)
        exit(1)

    clients["s4"].put_config(
        Bucket=args.bucket,
        Password=password,
        KeyType=args.key_type,
        KDFType=args.kdf_type,
        KDFParams=args.kdf_params,
        KOK=args.kok,
        Overwrite=args.overwrite,
    )

    print(f"Bucket {bucket} initialized")
