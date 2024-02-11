import argparse
import getpass
import itertools
import sys
from typing import Any

from .utils import Clients, paginate, parse_path


help = "delete objects from S3"


def parser(parser: argparse.ArgumentParser):
    parser.add_argument("path",
                        metavar="PATH")
    parser.add_argument("-R",
                        "--recursive",
                        action="store_true",
                        help="restores all objects under the specified buckets or prefixes")


def run(args: argparse.Namespace, clients: Clients):
    path = parse_path(args.path, assume_s4=True)
    if path.kind == "local":
        raise ValueError("path should be a S3 or S4 URI")

    delete_args: dict[str, Any] = {
        "Bucket": path.bucket
    }

    config = None
    if path.kind == "s4":
        password = getpass.getpass(f"Password for s4://{path.bucket}: ")
        config = clients["s4"].get_config(Bucket=path.bucket, Password=password)
        delete_args["S4Config"] = config

    if not args.recursive:
        delete_args["Key"] = path.key
        clients[path.kind].delete_object(**delete_args)
        print(f"delete: {path}")
    else:
        it = paginate(clients[path.kind], path.bucket, path.key, config)
        while keys := tuple(itertools.islice(it, 1000)):
            delete_args["Delete"] = {
                "Objects": [{"Key": key} for key in keys]
            }

            res = clients[path.kind].delete_objects(**delete_args)
            for deleted in res.get("Deleted", []):
                print(f"delete: {path.replace(key=deleted["Key"])}")
            for error in res.get("Errors", []):
                print(f"delete failed: {path.replace(key=error["Key"])}: {error["Message"]}", file=sys.stderr)
