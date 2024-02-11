import argparse
import getpass
from typing import Any

from .utils import Clients, parse_path


help = "list buckets or objects"

def parser(parser: argparse.ArgumentParser):
    parser.add_argument("path",
                        metavar="PATH",
                        nargs="?")
    parser.add_argument("-R",
                        "--recursive",
                        action="store_true",
                        help="list all objects under the specified bucket or prefix")


def run(args: argparse.Namespace, clients: Clients):
    if args.path is None:
        for bucket in clients["s3"].list_buckets().get("Buckets", []):
            name = bucket["Name"]
            creation_date = bucket["CreationDate"].astimezone().strftime("%Y-%m-%d %H:%M:%S")
            print(f"{creation_date} {name}")
        return

    path = parse_path(args.path, assume_s4=True)
    if path.kind == "local":
        raise ValueError("path should be a S3 or S4 URI")

    paginate_args: dict[str, Any] = {
        "Bucket": path.bucket,
        "Prefix": path.key,
    }
    if not args.recursive:
        paginate_args["Delimiter"] = "/"

    if path.kind == "s4":
        password = getpass.getpass(f"Password for s4://{path.bucket}: ")
        config = clients["s4"].get_config(Bucket=path.bucket, Password=password)
        paginate_args["S4Config"] = config

    paginator = clients[path.kind].get_paginator("list_objects_v2")
    for page in paginator.paginate(**paginate_args):
        for common_prefix in page.get("CommonPrefixes", []):
            prefix = common_prefix["Prefix"].split("/")[-2]
            print(f"{"PRE":>30s} {prefix}/")

        for content in page.get("Contents", []):
            last_mod = content["LastModified"].astimezone().strftime("%Y-%m-%d %H:%M:%S")
            size = content['Size']
            name = content['Key']
            if not args.recursive:
                name = name.split('/')[-1]
            print(f"{last_mod} {size:10d} {name}")
