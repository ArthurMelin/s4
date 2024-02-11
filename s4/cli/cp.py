import argparse
import getpass
import hashlib
import os
import subprocess
import threading
from typing import Any

import boto3.s3.transfer

from .. import crypto
from ..client import S4BucketConfig
from .utils import Clients, PathInfo, paginate, parse_path


help = "copy files and objects to and from S3"


def parser(parser: argparse.ArgumentParser):
    parser.add_argument("srcs",
                        metavar="SRC",
                        nargs="+")
    parser.add_argument("dest",
                        metavar="DEST")
    parser.add_argument("-R",
                        "--recursive",
                        action="store_true",
                        help="copy all files or objects under the specified directories, buckets or prefixes")
    parser.add_argument("--storage-class",
                        help="the type of storage to use for the objects")
    parser.add_argument("--cipher",
                        type=lambda s: s.lower(),
                        choices=crypto.cipher.algorithms.keys(),
                        default="chacha20poly1305",
                        help="the cipher to use for encrypting objects")


def run(args: argparse.Namespace, clients: Clients):
    transfer_config = _get_transfer_config(clients["s3"].meta._client_config.s3)
    s4_configs = {}

    extra_args = {}
    if args.storage_class:
        extra_args["StorageClass"] = args.storage_class

    dst = parse_path(args.dest)
    if dst.kind == "s4":
        password = getpass.getpass(f"Password for s4://{dst.bucket}: ")
        config = clients["s4"].get_config(Bucket=dst.bucket, Password=password)
        s4_configs[dst.bucket] = config.for_upload(Cipher=args.cipher)

    for src in args.srcs:
        src = parse_path(src)
        if src.kind == "s4" and src.bucket not in s4_configs:
            password = getpass.getpass(f"Password for s4://{src.bucket}: ")
            s4_configs[src.bucket] = clients["s4"].get_config(Bucket=src.bucket, Password=password)

        # resolve source key(s) and prefix
        if not args.recursive:
            src_keys = (src.key,)
        elif src.kind == "local":
            src_keys = (os.path.join(directory, file) for directory, _, files in os.walk(src.key, followlinks=True) for file in files)
        else:
            src_keys = paginate(clients[src.kind], src.bucket, src.key, s4_configs.get(src.bucket, None))
        src_prefix = len([c for c in src.key.split(os.path.sep if src.kind == "local" else "/") if c != ""])
        if not args.recursive and src_prefix > 0:
            src_prefix -= 1

        # iterate through source keys
        for src_key in src_keys:
            # resolve full destination key from source key and prefix
            if not args.recursive and len(args.srcs) == 1 and not dst.key == "" and not dst.key.endswith("/"):
                dst_key = dst.key
            else:
                src_key_cmps = [c for c in src_key.split(os.path.sep if src.kind == "local" else "/") if c != ""]
                src_key_cmps = src_key_cmps[src_prefix:]
                dst_key = os.path.join(dst.key, *src_key_cmps) if dst.kind == "local" else "/".join([dst.key, *src_key_cmps]).removeprefix("/")

            # make destination parent directories
            if dst.kind == "local":
                parent = os.path.split(dst_key)[0]
                if parent:
                    os.makedirs(parent, exist_ok=True)

            current_src = src.replace(key=src_key)
            current_dst = dst.replace(key=dst_key)

            # perform a copy if possible
            can_copy = src.kind == dst.kind and (src.kind != "s4" or src.bucket == dst.bucket)
            (_do_copy if can_copy else _do_transfer)(clients, current_src, current_dst, extra_args, s4_configs, transfer_config)


def _get_transfer_config(client_config: dict):
    transfer_config = boto3.s3.transfer.TransferConfig()
    transfer_config.max_in_memory_download_chunks = 6
    transfer_config.max_in_memory_upload_chunks = 6

    if (value := client_config.get("max_concurrent_requests", None)) is not None:
        transfer_config.max_request_concurrency = int(value)

    if (value := client_config.get("max_queue_size", None)) is not None:
        transfer_config.max_request_queue_size = int(value)

    for ckey, tkey in {
        "max_concurrent_requests": "max_request_concurrency",
        "max_queue_size": "max_request_queue_size",
        "multipart_threshold": "multipart_threshold",
        "multipart_chunksize": "multipart_chunksize",
        "max_bandwidth": "max_bandwidth",
    }.items():
        if (value := client_config.get(ckey, None)) is None:
            continue
        value = value.lower()

        if ckey in ("max_bandwidth"):
            if not value.endswith("/s"):
                raise ValueError(f"{ckey} must be expressed as a rate per second, e.g. '10MB/s'")
            value = value[:-2]

        if ckey in ("multipart_threshold", "multipart_chunksize", "max_bandwidth") and value[-1] == "b":
            suffix = value[-3:] if value[-2] == "i" else value[-2:]
            suffixes = {c: 1024**(i+1) for i, c in enumerate("kmgt")}
            if suffix[0] in suffixes:
                value = int(value[:-len(suffix)]) * suffixes[suffix[0]]
            else:
                value = int(value[:-len(suffix)+1])
        else:
            value = int(value)

        setattr(transfer_config, tkey, value)

    return transfer_config

def _do_copy(
    clients: Clients,
    src: PathInfo,
    dst: PathInfo,
    extra_args: dict[str, Any],
    s4_configs: dict[str, S4BucketConfig],
    transfer_config: boto3.s3.transfer.TransferConfig,
) -> None:
    if src.kind == "local":
        if os.name == "nt":
            cmd = ["xcopy", "/o", src.key, dst.key]
        elif os.name == "posix":
            cmd = ["cp", "-p", src.key, dst.key]
        else:
            raise NotImplementedError("unknown OS, just copy the file yourself dude")
        p = subprocess.run(cmd, capture_output=True, text=True)
        if p.returncode != 0:
            raise RuntimeError("cp command failed: " + p.stderr)
    else:
        if src.kind == "s4":
            extra_args["S4Config"] = s4_configs[src.bucket]
        clients[src.kind].copy(
            CopySource={
                "Bucket": src.bucket,
                "Key": src.key,
            },
            Bucket=dst.bucket,
            Key=dst.key,
            ExtraArgs=extra_args,
            Config=transfer_config,
        )
    print(f"copy: {src} to {dst}")

def _do_transfer(
    clients: Clients,
    src: PathInfo,
    dst: PathInfo,
    extra_args: dict[str, Any],
    s4_configs: dict[str, S4BucketConfig],
    transfer_config: boto3.s3.transfer.TransferConfig,
) -> None:
    src_extra_args = {}
    if src.kind == "s4":
        src_extra_args["S4Config"] = s4_configs[src.bucket]
    if dst.kind == "s4":
        extra_args["S4Config"] = s4_configs[dst.bucket]

    if src.kind == "local":
        assert dst.kind in ("s3", "s4")
        clients[dst.kind].upload_file(Filename=src.key, Bucket=dst.bucket, Key=dst.key, ExtraArgs=extra_args)
    elif dst.kind == "local":
        assert src.kind in ("s3", "s4")
        clients[src.kind].download_file(Bucket=src.bucket, Key=src.key, Filename=dst.key, ExtraArgs=src_extra_args)
    else:
        ringbuf = RingBuffer(transfer_config.multipart_chunksize)

        def _producer():
            assert src.kind in ("s3", "s4")
            clients[src.kind].download_fileobj(Bucket=src.bucket, Key=src.key, Fileobj=ringbuf, ExtraArgs=src_extra_args)
            ringbuf.close()

        def _consumer():
            assert dst.kind in ("s3", "s4")
            clients[dst.kind].upload_fileobj(Fileobj=ringbuf, Bucket=dst.bucket, Key=dst.key, ExtraArgs=extra_args)

        producer = threading.Thread(target=_producer)
        consumer = threading.Thread(target=_consumer)
        producer.start()
        consumer.start()
        producer.join()
        consumer.join()
        ringbuf.sanity_check()

        # TODO: catch exception in threads

    labels = {
        "local-s3": "upload",
        "local-s4": "upload",
        "s3-local": "download",
        "s4-local": "download",
        "s3-s4": "transfer",
        "s4-s3": "transfer",
    }
    label = labels[f"{src.kind}-{dst.kind}"]
    print(f"{label}: {src} to {dst}")


class RingBuffer:
    def __init__(self, capacity: int):
        self.__capacity = capacity
        self.__buffer = b""
        self.__closed = False
        self.__condition = threading.Condition()
        self.__in_hash = hashlib.sha256()
        self.__out_hash = hashlib.sha256()

    def read(self, size: int = -1, /):
        res = b""
        with self.__condition:
            while size == -1 or len(res) < size:
                while len(self.__buffer) == 0:
                    if self.__closed:
                        self.__out_hash.update(res)
                        return res
                    self.__condition.wait()
                chunksz = len(self.__buffer) if size == -1 else min(size - len(res), len(self.__buffer))
                chunk = self.__buffer[:chunksz]
                self.__buffer = self.__buffer[chunksz:]
                res += chunk
                self.__condition.notify_all()
        self.__out_hash.update(res)
        return res

    def write(self, b: bytes, /):
        self.__in_hash.update(b)
        off = 0
        with self.__condition:
            while off < len(b):
                while len(self.__buffer) >= self.__capacity:
                    if self.__closed:
                        raise IOError("File is closed")
                    self.__condition.wait()
                chunksz = max(len(b) - off, self.__capacity - len(self.__buffer))
                chunk = b[off:off+chunksz]
                self.__buffer += chunk
                off += chunksz
                self.__condition.notify_all()

    def close(self):
        with self.__condition:
            self.__closed = True
            self.__condition.notify_all()

    def sanity_check(self):
        if self.__in_hash.digest() != self.__out_hash.digest():
            raise RuntimeError(f"I/O checksum mismatch (in: {self.__in_hash.hexdigest()}, out: {self.__out_hash.hexdigest()})")
