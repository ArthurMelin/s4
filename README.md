# s4
S4 is an extension to AWS S3 with customizable **client-side** encryption.

S4 works using a bucket-level *User Key*, which is derived from a password. Each object can be encrypted using a variety of symmetric ciphers. The encryption key is wrapped using the user key and stored along other information in the object metadata. Each object's key (its URI) is also obfuscated with a separate Key Obfuscation Key.

This implementation of a S4 client is a wrapper of the Python boto3 S3 client with patches to operations to handle transparent encryption/decryption and key de/obfuscation.

A CLI is also provided in this repo which mimicks the AWS CLI commands but with S4 support.

## Requirements:
* Python 3.12+
* OpenSSL 3.2.0+

## Getting started

Before starting, configure the AWS CLI to access S3 or whatever compatible service you want to use, and create a bucket to use with S4.

### 1. Install s4
If you haven't already, install S4 and the CLI:
```shell
pip install git+https://github.com/ArthurMelin/s4
```

### 2. Initialize the bucket
To begin start your bucket with S4, you must first initialize it. You will be prompted for a password and again to confirm it. This password will be used to derive your User Key (or encrypt it) and later each time you want to access and modify objects in the bucket.
```shell
s4 init my-bucket
```

This command has a few optional arguments which allow you to choose which User Key type or KDF to use.

The current default key type is **X448** with a private key derived from your password using the **Argon2ID** KDF.

### 3. Upload an object
Once the bucket is initialized, you can start using the bucket as if it was a S3 bucket with the s4 CLI:
```shell
s4 cp file.txt s4://my-bucket
s4 ls s4://my-bucket
s4 cp s4://my-bucket/file.txt ./
```
When uploading files, you can choose which cipher to use to encrypt the file using the `--cipher` argument.

The current default cipher is ChaCha20-Poly1305.

You can also use the S4 cli with normal S3 buckets and objects by using the `s3://` prefix.

## Specification

### Bucket configuration
* Key: `config.json`
* Contents:
    ```js
    {
        "kdf": "<Key Derivation Function algorithm id>",
        "kdf_params": { /* KDF-specific parameters */ },
        "key": "<User key type id>",
        "key_fp": "<User key fingerprint>",
        "kok": "<Wrapped key obfuscation key>"
    }
    ```
<sub><sub>Remember, you should always wrap your KOK 😏</sub></sub>

### Key obfuscation
This algorithm is used to obfuscate object keys (its URI/path in the bucket).

The reference implementation can be found in `s4/client.py` in the `S4BucketConfig` class.

The plain key is split into parts using the "/" delimiter, then for each part:
* A 64 bits nonce is derived from a SHAKE-256 hash of the bucket and plain key up to the current part.
* The part is encrypted using the ChaCha20 cipher with the Key Obfuscation Key and nonce.
* The nonce and cipher output are concatenated and encoded using base64url (without padding "=")

All encrypted parts are then joined again with the "/" delimiter and prepended with a "$".

The deobfuscation process works in reverse but uses the nonce included in the obfuscated key to decrypt it.

### Encrypted object metadata
* `s4-alg`: `"<Cipher algorithm id>"`
* `s4-iv`: `"<Cipher IV base64>"`
* `s4-key`: `"<Wrapped cipher key>"`

The cipher key is wrapped using the User Key.

### Encrypted object body
The object body is encrypted with the selected cipher. It may be appended with an authentication tag if the selected cipher is an AEAD.
