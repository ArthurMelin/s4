import base64
import hashlib
import json
from dataclasses import dataclass
from types import MethodType
from typing import Callable, Optional, Protocol, cast

import botocore.client
import botocore.exceptions
import botocore.paginate
import boto3.s3.transfer
import boto3.session
import s3transfer.copies
import s3transfer.manager
import s3transfer.upload

from . import crypto


# patch s3transfer allowed args
s3transfer.manager.TransferManager.ALLOWED_COPY_ARGS.append("S4Config")
s3transfer.manager.TransferManager.ALLOWED_DOWNLOAD_ARGS.append("S4Config")
s3transfer.manager.TransferManager.ALLOWED_UPLOAD_ARGS.append("S4Config")
s3transfer.copies.CopySubmissionTask.EXTRA_ARGS_TO_HEAD_ARGS_MAPPING["S4Config"] = "S4Config"
s3transfer.copies.CopySubmissionTask.UPLOAD_PART_COPY_ARGS.append("S4Config")
s3transfer.copies.CopySubmissionTask.COMPLETE_MULTIPART_ARGS.append("S4Config")
s3transfer.upload.UploadSubmissionTask.UPLOAD_PART_ARGS.append("S4Config")
s3transfer.upload.UploadSubmissionTask.COMPLETE_MULTIPART_ARGS.append("S4Config")


__all__ = [
    "S3",
    "S3Interface",
    "S4",
    "S4Interface",
    "S4BucketConfig",
    "S4UploadConfig",
]


class S3Interface(Protocol):
    def abort_multipart_upload(self, **kwargs) -> dict: ...
    def complete_multipart_upload(self, **kwargs) -> dict: ...
    def copy_object(self, **kwargs) -> dict: ...
    def create_multipart_upload(self, **kwargs) -> dict: ...
    def delete_object(self, **kwargs) -> dict: ...
    def delete_objects(self, **kwargs) -> dict: ...
    def get_object(self, **kwargs) -> dict: ...
    def head_bucket(self, **kwargs) -> dict: ...
    def head_object(self, **kwargs) -> dict: ...
    def list_buckets(self) -> dict: ...
    def list_objects_v2(self, **kwargs) -> dict: ...
    def put_object(self, **kwargs) -> dict: ...
    def restore_object(self, **kwargs) -> dict: ...
    def upload_part_copy(self, **kwargs) -> dict: ...
    def upload_part(self, **kwargs) -> dict: ...

    def copy(
        self,
        CopySource: dict,
        Bucket: str,
        Key: str,
        ExtraArgs: Optional[dict] = None,
        Callback: Optional[Callable[[int], None]] = None,
        Config: Optional[boto3.s3.transfer.TransferConfig] = None,
    ) -> dict: ...
    def download_file(
        self,
        Bucket: str,
        Key: str,
        Filename: str,
        ExtraArgs: Optional[dict] = None,
        Callback: Optional[Callable[[int], None]] = None,
        Config: Optional[boto3.s3.transfer.TransferConfig] = None,
    ) -> dict: ...
    def download_fileobj(
        self,
        Bucket: str,
        Key: str,
        Fileobj,
        ExtraArgs: Optional[dict] = None,
        Callback: Optional[Callable[[int], None]] = None,
        Config: Optional[boto3.s3.transfer.TransferConfig] = None,
    ) -> dict: ...
    def upload_file(
        self,
        Filename: str,
        Bucket: str,
        Key: str,
        ExtraArgs: Optional[dict] = None,
        Callback: Optional[Callable[[int], None]] = None,
        Config: Optional[boto3.s3.transfer.TransferConfig] = None,
    ) -> dict: ...
    def upload_fileobj(
        self,
        Fileobj,
        Bucket: str,
        Key: str,
        ExtraArgs: Optional[dict] = None,
        Callback: Optional[Callable[[int], None]] = None,
        Config: Optional[boto3.s3.transfer.TransferConfig] = None,
    ) -> dict: ...

    def get_paginator(self, operation_name: str) -> botocore.paginate.Paginator: ...


def S3(
    aws_access_key_id: Optional[str] = None,
    aws_secret_access_key: Optional[str] = None,
    aws_session_token: Optional[str] = None,
    region_name: Optional[str] = None,
    profile_name: Optional[str] = None,
    api_version: Optional[str] = None,
    use_ssl: bool = True,
    verify: Optional[bool | str] = None,
    endpoint_url: Optional[str] = None,
    config: Optional[botocore.client.Config] = None
) -> S3Interface:
    session = boto3.session.Session(
        aws_access_key_id=aws_access_key_id,
        aws_secret_access_key=aws_secret_access_key,
        aws_session_token=aws_session_token,
        region_name=region_name,
        profile_name=profile_name,
    )

    return cast(S3Interface, session.client(
        "s3",
        api_version=api_version,
        use_ssl=use_ssl,
        verify=verify,
        endpoint_url=endpoint_url,
        config=config,
    ))


class S4:
    """
    Wrapper around S3 client to add transparent en/decryption and key de/obfuscation.
    Only some of the client operations are currently implemented.
    """

    def __init__(self, s3: S3Interface):
        self.__s3 = s3

    def __getattr__(self, __name: str):
        ret = getattr(self.__s3, __name)
        if type(ret) == MethodType:
            # print("RAW ACCESS", __name)
            # Rebind the method from the S3 client instance to this instance (self)
            ret = MethodType(ret.__func__, self)
        return ret

    def get_config(
        self,
        Bucket: str,
        Password: str
    ):
        try:
            config = json.load(self.__s3.get_object(Bucket=Bucket, Key="config.json")["Body"])
        except botocore.exceptions.ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchKey":
                raise TypeError("S4 configuration not found")
            raise e

        # Decrypt/derive user key
        key_type = config.get("key", None)
        if key_type is None:
            raise ValueError("missing key type in config")
        if key_type not in crypto.pkey.algorithms:
            raise ValueError(f"unknown key type {key_type} in config")
        key_cls = crypto.pkey.algorithms[key_type]
        if issubclass(key_cls, crypto.pkey.UserKeyRawKey):
            kdf_type = config.get("kdf", None)
            if kdf_type is None:
                raise ValueError("missing kdf type in config")
            if kdf_type not in crypto.kdf.algorithms:
                raise ValueError(f"unknown kdf type {kdf_type} in config")
            kdf_cls = crypto.kdf.algorithms[kdf_type]
            kdf = kdf_cls(config.get("kdf_params", None))
            secret = kdf.derive(Password.encode("utf-8"), key_cls.raw_key_length())
            Key = key_cls(secret)
        else:
            raise NotImplementedError()

        # Check user key fingerprint
        if Key.fingerprint() != config["key_fp"]:
            raise ValueError("Key fingerprint mismatch")

        # Unwrap key obfuscation key
        KOK = Key.unwrap(config["kok"])

        return S4BucketConfig(Bucket=Bucket, UserKey=Key, KOK=KOK)

    def put_config(
        self,
        Bucket: str,
        Password: str,
        Key: Optional[crypto.pkey.UserKey] = None,
        KeyType: Optional[str] = None,
        KDFType: Optional[str] = None,
        KDFParams: Optional[dict[str, str]] = None,
        KOK: Optional[bytes] = None,
        Overwrite: bool = False,
    ):
        # Check for a preexisting config
        if not Overwrite:
            self.__s3.head_bucket(Bucket=Bucket)
            try:
                self.__s3.head_object(Bucket=Bucket, Key="config.json")
                raise TypeError("S4 configuration already present, not overwriting")
            except botocore.exceptions.ClientError as e:
                if e.response["Error"]["Code"] != "404":
                    raise e

        # Check params
        need_kdf = False
        if Key is None and KeyType is None:
            raise TypeError("key or key_type must be specified")
        if Key is not None:
            KeyType = {v: k for k, v in crypto.pkey.algorithms.items()}[type(Key)]
        assert KeyType is not None # fix pylance dumbass warning
        if Key is None:
            if KeyType not in crypto.pkey.algorithms:
                raise ValueError("invalid key type " + KeyType)
            key_cls = crypto.pkey.algorithms[KeyType]
            if issubclass(key_cls, crypto.pkey.UserKeyRawKey):
                need_kdf = True
            else:
                raise NotImplementedError()
        if need_kdf:
            if KDFType is None:
                raise TypeError("kdf_type must be specified with selected key type")
            if KDFType not in crypto.kdf.algorithms:
                raise ValueError("invalid kdf type " + KDFType)
        if KOK is not None and len(KOK) != 32:
            raise ValueError("key obfuscation key must be 32 bytes")

        # Generate/derive user key
        if Key is None:
            key_cls = crypto.pkey.algorithms[KeyType]
            if issubclass(key_cls, crypto.pkey.UserKeyRawKey):
                assert KDFType is not None
                kdf_cls = crypto.kdf.algorithms[KDFType]
                kdf = kdf_cls(KDFParams)
                KDFParams = kdf.params
                secret = kdf.derive(Password.encode("utf-8"), key_cls.raw_key_length())
                Key = key_cls(secret)
            else:
                raise NotImplementedError()

        # Generate key obfuscation key
        if KOK is None:
            KOK = crypto.libcrypto.random_bytes(32)

        # Upload config
        config = {
            **({"kdf": KDFType, "kdf_params": KDFParams} if need_kdf else {}),
            "key": KeyType,
            "key_fp": Key.fingerprint(),
            "kok": Key.wrap(KOK),
        }
        self.__s3.put_object(
            Bucket=Bucket,
            Key="config.json",
            Body=json.dumps(config, indent=2).encode("utf-8"),
        )

        return S4BucketConfig(Bucket=Bucket, UserKey=Key, KOK=KOK)

    def download_file(
        self,
        Bucket: str,
        Key: str,
        Filename: str,
        ExtraArgs: dict,
        Callback: Optional[Callable[[int], None]] = None,
        Config: Optional[boto3.s3.transfer.TransferConfig] = None,
    ) -> dict:
        with open(Filename, "wb") as Fileobj:
            return self.download_fileobj(
                Bucket=Bucket,
                Key=Key,
                Fileobj=Fileobj,
                ExtraArgs=ExtraArgs,
                Callback=Callback,
                Config=Config,
            )

    def download_fileobj(
        self,
        Bucket: str,
        Key: str,
        Fileobj,
        ExtraArgs: dict,
        Callback: Optional[Callable[[int], None]] = None,
        Config: Optional[boto3.s3.transfer.TransferConfig] = None,
    ) -> dict:
        config: S4BucketConfig = ExtraArgs["S4Config"]

        # Get metadata
        head = self.head_object(Bucket=Bucket, Key=Key, S4Config=config)
        metadata = head.get("Metadata", {})
        alg = metadata.get("s4-alg", None)
        iv = metadata.get("s4-iv", None)
        key = metadata.get("s4-key", None)
        if any(x is None for x in (alg, iv, key)):
            raise ValueError("object is missing s4 metadata")

        # Init cipher
        if alg not in crypto.cipher.algorithms:
            raise ValueError("unknown cipher " + alg)
        cipher_cls = crypto.cipher.algorithms[alg]
        key = config.UserKey.unwrap(key)
        iv = base64.b64decode(iv)
        cipher = cipher_cls(enc=False, key=key, iv=iv)

        # Wrap fileobj
        class FileobjDecryptor:
            def __init__(self):
                self._aead = isinstance(cipher, crypto.cipher.AEAD)
                if self._aead:
                    assert isinstance(cipher, crypto.cipher.AEAD)
                    self._wrsz = 0
                    self._tag = b""
                    self._tagsz = cipher.get_auth_tag_len()
                    self._objsz = int(head["ContentLength"]) - self._tagsz

            def write(self, b: bytes, /):
                if self._aead:
                    if self._wrsz >= self._objsz:
                        self._tag += b
                        return
                    elif self._wrsz + len(b) > self._objsz:
                        s = self._objsz - self._wrsz
                        self._tag += b[s:]
                        b = b[:s]
                    self._wrsz += len(b)
                b = cipher.update(b)
                Fileobj.write(b)

            def close(self):
                if self._aead:
                    assert isinstance(cipher, crypto.cipher.AEAD)
                    if len(self._tag) != self._tagsz:
                        raise ValueError("invalid auth tag length at end of data")
                    cipher.set_auth_tag(self._tag)
                b = cipher.final()
                Fileobj.write(b)

        FileobjDec = FileobjDecryptor()

        res = self.__getattr__("download_fileobj")(
            Bucket=Bucket,
            Key=Key,
            Fileobj=FileobjDec,
            ExtraArgs=ExtraArgs,
            Callback=Callback,
            Config=Config,
        )

        FileobjDec.close()
        return res

    def upload_file(
        self,
        Filename: str,
        Bucket: str,
        Key: str,
        ExtraArgs: dict,
        Callback: Optional[Callable[[int], None]] = None,
        Config: Optional[boto3.s3.transfer.TransferConfig] = None,
    ) -> dict:
        with open(Filename, "rb") as Fileobj:
            return self.upload_fileobj(
                Bucket=Bucket,
                Key=Key,
                Fileobj=Fileobj,
                ExtraArgs=ExtraArgs,
                Callback=Callback,
                Config=Config,
            )

    def upload_fileobj(
        self,
        Fileobj,
        Bucket: str,
        Key: str,
        ExtraArgs: dict,
        Callback: Optional[Callable[[int], None]] = None,
        Config: Optional[boto3.s3.transfer.TransferConfig] = None,
    ) -> dict:
        config: S4UploadConfig = ExtraArgs["S4Config"]

        # Init cipher
        if config.Cipher not in crypto.cipher.algorithms:
            raise ValueError("unknown cipher " + config.Cipher)
        cipher_cls = crypto.cipher.algorithms[config.Cipher]
        key = crypto.libcrypto.random_bytes(cipher_cls.get_key_len())
        iv = crypto.libcrypto.random_bytes(cipher_cls.get_iv_len())
        cipher = cipher_cls(enc=True, key=key, iv=iv)

        # Set metadata
        if not "Metadata" in ExtraArgs:
            ExtraArgs["Metadata"] = {}
        ExtraArgs["Metadata"]["s4-alg"] = config.Cipher
        ExtraArgs["Metadata"]["s4-iv"] = base64.b64encode(iv).decode()
        ExtraArgs["Metadata"]["s4-key"] = config.UserKey.wrap(key)

        # Wrap fileobj
        class FileobjEncryptor:
            def __init__(self):
                self._eof = False

            def read(self, size: int = -1, /):
                if self._eof:
                    return b""
                b = Fileobj.read(size)
                res = b""
                if b:
                    res += cipher.update(b)
                if not b or size == -1 or len(b) < size:
                    self._eof = True
                    res += cipher.final()
                    if isinstance(cipher, crypto.cipher.AEAD):
                        res += cipher.get_auth_tag()
                return res

        FileobjEnc = FileobjEncryptor()

        return self.__getattr__("upload_fileobj")(
            Bucket=Bucket,
            Key=Key,
            Fileobj=FileobjEnc,
            ExtraArgs=ExtraArgs,
            Callback=Callback,
            Config=Config,
        )

    def list_objects_v2(self, **kwargs):
        config: S4BucketConfig = kwargs.pop("S4Config")
        if "Prefix" in kwargs:
            kwargs["Prefix"] = config.obfuscate_key(kwargs["Prefix"])
        res = self.__s3.list_objects_v2(**kwargs)
        for common_prefix in res.get("CommonPrefixes", []):
            common_prefix["Prefix"] = config.deobfuscate_key(common_prefix["Prefix"])
        for content in res.get("Contents", []):
            content["Key"] = config.deobfuscate_key(content["Key"])
        res["Prefix"] = config.deobfuscate_key(res["Prefix"])
        return res

    def head_object(self, **kwargs):
        config: S4BucketConfig = kwargs.pop("S4Config")
        kwargs["Key"] = config.obfuscate_key(kwargs["Key"])
        return self.__s3.head_object(**kwargs)

    def get_object(self, **kwargs):
        """DOESN'T SUPPORT TRANSPARENT DECRYPTION"""
        config: S4BucketConfig = kwargs.pop("S4Config")
        kwargs["Key"] = config.obfuscate_key(kwargs["Key"])
        return self.__s3.get_object(**kwargs)

    def put_object(self, **kwargs):
        """DOESN'T SUPPORT TRANSPARENT ENCRYPTION"""
        config: S4BucketConfig = kwargs.pop("S4Config")
        kwargs["Key"] = config.obfuscate_key(kwargs["Key"])
        return self.__s3.put_object(**kwargs)

    def copy_object(self, **kwargs):
        if not isinstance(kwargs["CopySource"], dict):
            raise TypeError("CopySource should be specified as a dict")
        if kwargs["CopySource"]["Bucket"] != kwargs["Bucket"]:
            raise TypeError("S4 copy_object can only copy within a bucket")
        config: S4BucketConfig = kwargs.pop("S4Config")
        kwargs["CopySource"]["Key"] = config.obfuscate_key(kwargs["CopySource"]["Key"])
        kwargs["Key"] = config.obfuscate_key(kwargs["Key"])
        return self.__s3.copy_object(**kwargs)

    def delete_object(self, **kwargs):
        config: S4BucketConfig = kwargs.pop("S4Config")
        kwargs["Key"] = config.obfuscate_key(kwargs["Key"])
        return self.__s3.delete_object(**kwargs)

    def delete_objects(self, **kwargs):
        config: S4BucketConfig = kwargs.pop("S4Config")
        for object in kwargs.get("Delete", {}).get("Objects", []):
            object["Key"] = config.obfuscate_key(object["Key"])
        res = self.__s3.delete_objects(**kwargs)
        for deleted in res.get("Deleted", []):
            deleted["Key"] = config.deobfuscate_key(deleted["Key"])
        for error in res.get("Errors", []):
            error["Key"] = config.deobfuscate_key(error["Key"])
        return res

    def restore_object(self, **kwargs):
        config: S4BucketConfig = kwargs.pop("S4Config")
        kwargs["Key"] = config.obfuscate_key(kwargs["Key"])
        return self.__s3.restore_object(**kwargs)

    def create_multipart_upload(self, **kwargs):
        config: S4BucketConfig = kwargs.pop("S4Config")
        kwargs["Key"] = config.obfuscate_key(kwargs["Key"])
        return self.__s3.create_multipart_upload(**kwargs)

    def abort_multipart_upload(self, **kwargs):
        config: S4BucketConfig = kwargs.pop("S4Config")
        kwargs["Key"] = config.obfuscate_key(kwargs["Key"])
        return self.__s3.abort_multipart_upload(**kwargs)

    def complete_multipart_upload(self, **kwargs):
        config: S4BucketConfig = kwargs.pop("S4Config")
        kwargs["Key"] = config.obfuscate_key(kwargs["Key"])
        return self.__s3.complete_multipart_upload(**kwargs)

    def upload_part(self, **kwargs):
        config: S4BucketConfig = kwargs.pop("S4Config")
        kwargs["Key"] = config.obfuscate_key(kwargs["Key"])
        return self.__s3.upload_part(**kwargs)

    def upload_part_copy(self, **kwargs):
        if not isinstance(kwargs["CopySource"], dict):
            raise TypeError("CopySource should be specified as a dict")
        if kwargs["CopySource"]["Bucket"] != kwargs["Bucket"]:
            raise TypeError("S4 copy_object can only copy within a bucket")
        config: S4BucketConfig = kwargs.pop("S4Config")
        kwargs["CopySource"]["Key"] = config.obfuscate_key(kwargs["CopySource"]["Key"])
        kwargs["Key"] = config.obfuscate_key(kwargs["Key"])
        return self.__s3.upload_part_copy(**kwargs)


class S4Interface(S3Interface, S4):
    pass


@dataclass
class S4BucketConfig:
    Bucket: str
    UserKey: crypto.pkey.UserKey
    KOK: bytes

    def obfuscate_key(self, plain_key: str) -> str:
        bucket_bytes = self.Bucket.encode("utf-8")
        key_bytes = plain_key.encode("utf-8")
        key_parts = key_bytes.split(b"/")
        res_parts = []
        for i, key_part in enumerate(key_parts):
            if len(key_part) == 0:
                res_parts.append("")
                continue
            nonce = hashlib.shake_256(bucket_bytes + b'/' + b"/".join(key_parts[:i+1])).digest(8)
            cipher = crypto.cipher.ChaCha20(True, self.KOK, nonce)
            res = nonce
            res += cipher.update(key_part)
            res += cipher.final()
            res_parts.append(base64.urlsafe_b64encode(res).replace(b"=", b"").decode("utf-8"))
        return "$" + "/".join(res_parts)

    def deobfuscate_key(self, obf_key: str) -> str:
        if not obf_key.startswith("$"):
            raise ValueError("key is not a S4 obfuscated key")
        obf_parts = obf_key[1:].split("/")
        res_parts = []
        for obf_part in obf_parts:
            if len(obf_part) == 0:
                res_parts.append("")
                continue
            decoded = base64.urlsafe_b64decode(obf_part.encode("utf-8") + b"====")
            nonce = decoded[0:8]
            key_bytes = decoded[8:]
            cipher = crypto.cipher.ChaCha20(False, self.KOK, nonce)
            res = cipher.update(key_bytes)
            res += cipher.final()
            res_parts.append(res.decode("utf-8"))
        return "/".join(res_parts)

    def for_upload(self, Cipher: str):
        return S4UploadConfig(Bucket=self.Bucket, UserKey=self.UserKey, KOK=self.KOK, Cipher=Cipher)

@dataclass
class S4UploadConfig(S4BucketConfig):
    Cipher: str
