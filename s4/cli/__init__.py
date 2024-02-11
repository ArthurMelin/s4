import argparse
import os
import sys
from typing import cast

import botocore.configloader

from ..client import S3, S4, S4Interface
from .utils import Clients, MergingSubparsersAction


cmds = {name: __import__(name, globals(), locals(), level=1) for name in ["init", "ls", "cp", "rm", "restore"]}

common_parser = argparse.ArgumentParser(add_help=False)
common_parser.add_argument("--profile", help="use a specific profile from the configuration file")
common_parser.add_argument("--region", help="use a specifc region")
common_parser.add_argument("--endpoint-url", help="use a specific endpoint URL")
common_parser.add_argument("--no-verify-ssl", action="store_true", help="disables verifying SSL certificates")

main_parser = argparse.ArgumentParser(
    prog="s4",
    description="AWS S3 CLI with customizable client-side encryption",
    parents=[common_parser],
)
subparsers = main_parser.add_subparsers(title="commands", dest="cmd", required=True, action=MergingSubparsersAction)
for name, mod in cmds.items():
    mod.parser(subparsers.add_parser(name, parents=[common_parser], help=mod.help))


def main():
    # parse cli args
    args = main_parser.parse_args()

    # configure client
    endpoint_url = args.endpoint_url
    cli_config_path = os.getenv("AWS_CONFIG_FILE") or "~/.aws/config"
    cli_config = botocore.configloader.load_config(cli_config_path)
    cli_s3_config = cli_config.get("profiles", {}).get(args.profile or "default", {}).get("s3", {})
    if endpoint_url is None:
        endpoint_url = cli_s3_config.get("endpoint_url", None)

    # instantiate s3 and s4 clients
    s3_client = S3(
        region_name=args.region,
        profile_name=args.profile,
        endpoint_url=endpoint_url,
        verify=False if args.no_verify_ssl else None,
    )
    s4_client = S4(s3_client)
    clients = Clients(s3=s3_client, s4=cast(S4Interface, s4_client))

    # run the command
    try:
        cmds[args.cmd].run(args, clients)
    except Exception as e:
        print(f"{main_parser.prog}:", *e.args if len(e.args) else (e.__class__.__name__,), file=sys.stderr)
        exit(1)
