import argparse
from typing import Any, Generator, Literal, NamedTuple, Optional, TypedDict, cast

from ..client import S3Interface, S4Interface, S4BucketConfig


class Clients(TypedDict):
    s3: S3Interface
    s4: S4Interface


class MergingSubparsersAction(argparse._SubParsersAction):
    '''Patched `argparse` subparsers action to properly merge common parent/child parser args'''
    def __call__(self, parser, namespace, values, option_string=None):
        subnamespace = argparse.Namespace()
        super().__call__(parser, subnamespace, values, option_string=option_string)
        for key, value in vars(subnamespace).items():
            if hasattr(namespace, key) and value == next(a for a in parser._actions if a.dest == key).default:
                continue
            setattr(namespace, key, value)


class PathInfo(NamedTuple):
    kind: Literal["local", "s3", "s4"]
    bucket: str
    key: str

    def __str__(self):
        if self.kind == "local":
            return self.key
        return f"{self.kind}://{self.bucket}/{self.key}"

    def replace(self,
                kind: Optional[Literal["local", "s3", "s4"]] = None,
                bucket: Optional[str] = None,
                key: Optional[str] = None):
        return PathInfo(kind or self.kind, bucket or self.bucket, key or self.key)


def parse_path(path: str, assume_s4=False) -> PathInfo:
    '''Parse a local path, S3 URI or S4 URI'''
    if path.lower().startswith("s3://"):
        kind = "s3"
        path = path[5:]
    elif path.lower().startswith("s4://"):
        kind = "s4"
        path = path[5:]
    elif assume_s4 and path[0].isalnum():
        kind = "s4"
    else:
        kind = "local"

    if kind in ("s3", "s4"):
        if len(path) == 0:
            raise ValueError(f"invalid empty {kind.upper()} URI")
        bucket, *key = path.split("/", 1)
        key = key[0] if len(key) != 0 else ""
        return PathInfo(kind, bucket, key)
    else:
        if path == "-":
            raise NotImplementedError("streaming to/from stdio is not supported yet")
        return PathInfo(kind, "", path)


def paginate(client: S3Interface,
             bucket: str,
             prefix: str,
             config: S4BucketConfig | None) -> Generator[str, None, None]:
    '''Paginate keys from a S3/S4 prefix'''
    paginate_args: dict[str, Any] = {
        "Bucket": bucket,
        "Prefix": prefix,
    }
    if config is not None:
        paginate_args["S4Config"] = config

    paginator = client.get_paginator("list_objects_v2")
    for page in paginator.paginate(**paginate_args):
        yield from map(lambda c: cast(str, c["Key"]), page.get("Contents", []))
