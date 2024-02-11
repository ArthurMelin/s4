import argparse
import getpass
from typing import Any

from .utils import Clients, paginate, parse_path


help = "restore objects from S3 Glacier"


def parser(parser: argparse.ArgumentParser):
    parser.add_argument("path",
                        metavar="PATH")
    parser.add_argument("-R",
                        "--recursive",
                        action="store_true",
                        help="restores all objects under the specified buckets or prefixes")
    parser.add_argument("--days",
                        type=int,
                        required=True,
                        help="lifetime of the restored copy in days")
    parser.add_argument("--tier",
                        choices=("Standard", "Bulk", "Expedited"),
                        help="retrieval tier at which the restore will be processed")


def run(args: argparse.Namespace, clients: Clients):
    path = parse_path(args.path, assume_s4=True)
    if path.kind == "local":
        raise ValueError("path should be a S3 or S4 URI")

    restore_args: dict[str, Any] = {
        "Bucket": path.bucket,
        "Key": "",
        "RestoreRequest": {
            "Days": args.days,
        }
    }
    if args.tier is not None:
        restore_args["RestoreRequest"]["Tier"] = args.tier

    config = None
    if path.kind == "s4":
        password = getpass.getpass(f"Password for s4://{path.bucket}: ")
        config = clients["s4"].get_config(Bucket=path.bucket, Password=password)
        restore_args["S4Config"] = config

    if not args.recursive:
        keys = [path.key]
    else:
        keys = paginate(clients[path.kind], path.bucket, path.kind, config)

    for key in keys:
        restore_args["Key"] = key
        clients[path.kind].restore_object(**restore_args)
        print(f"restore: {path.replace(key=key)}")
