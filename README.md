# Dyndynser

The purpose of this program is to securely request DDNS updates over Route53. The scope of this project is limited entirely to AWS EC2 instances which have a role for S3 buckets.

Dyndynser runs in two modes: Client Mode, and Server Mode.

# Building

## Requirements

* Rust 1.70+
  
```
cargo build
```

# AWS Requirements
* Writeable S3 bucket to store ddns request info

# Runtime / Environment Requirements

## Both
* Running on an AWS EC2 instance

## Client
* Permissions: EC2 Instance Role with IAM priveldges for `s3:write` to your bucket of choice
* Firewall: Ability to query `https://checkip.amazonaws.com` for an ip
* An ED25519 _Private_ Key for the domain to sign for
  * formats include: `openssh`, and `ssh-keygen`, either is fine
  * password optional


## Server
* Permissions: 
  * EC2 Instance Role with IAM priveliges for `s3:read` from your bucket of choice
  * EC2 Instance Role with IAM privelides for `route53:read,write` to your main domain 
* An Ed25519 _Public_ Key of each domain to validate ddns requests for
* [ddns-route53](https://github.com/crazy-max/ddns-route53) and a `ddns.yaml` file


# Usage
Before using either the client or server, gernate an ed25119 public / private keypair for each domain you wish to make requests on behalf of:

1. Generate an ed25519 Public Private keypair.
   *  the name of the keypair should match the domain you intend to use it to sign for. In this example, we are signing for `sub.example.com`
    ### OpenSSH
    ```bash
    ssh-keygen -t ed25519 -f sub.example.com
    mv sub.example.com sub.example.com.priv
    ```
    or 
    ### OpenSSL
    ```bash
    openssl genpkey -algorithm ed25519 -out sub.example.com.priv
    openssl pkey -in sub.example.com.priv -pubout -out sub.example.com.pub
    ```

2. Move the public key to the Server's `$dyndynser/known_keys/` directory
    ```bash
    mv sub.example.com.pub $dyndynser/known_keys
    ```
3. Move the private key to any safe space on the Client EC2 instance

## Client


Assume the following environment variables: `signingkey=path/to/sub.example.com.priv`, `region=us-east-1`, `s3bucket=somebucket`, `domain=sub.example.com`, `s3path=/ddns/domains` and assume that the key is _not_ password protected:

### Help:
```bash
Usage: dyndynser client [OPTIONS] <ROBOCERTS_BUCKET> <S3_DDNS_JSON_DIR> <DOMAIN> <KEY_PATH> <REGION>

Arguments:
  <ROBOCERTS_BUCKET>
  <S3_DDNS_JSON_DIR>
  <DOMAIN>
  <KEY_PATH>
  <REGION>

Options:
      --signing-key-password <SIGNING_KEY_PASSWORD>
      --dry-run
  -h, --help
```

### Dry Run, test what will be written:
```bash
dyndynser client --dry-run $s3bucket $s3path $signingkey $region
Will write to: s3://somebucket/ddns/domains/sub.example.com.ddns.json
JSON:
{
  "payload": {
    "domain": "sub.example.com",
    "ip": "200.100.50.25"
  },
  "signature": "f94a75062c62be661fe353d5330c659f742e8e51be4b477c5f4256cb220b3659c01c4680bb9b2db5198b9d8eeb2d5fa4a1d0857df68d71c1913bf1ce72d7f403"
}
```

A successful dry run _does not_ mean that the S3 connection is successful, you will need to actually run it to find out. Alternatively, you can use, e.g, the aws s3 sdk to investigate:
```bash
aws s3api list-objects-v2 --bucket $s3bucket
{
    "Contents": [
        {
            "Key": "ddns/domains/sub.example.com.ddns.json",
            "LastModified": "2026-05-01T05:22:45+00:00",
            "ETag": "\"526f2dcba8bd205387e39d092ab6fe0c\"",
            "ChecksumAlgorithm": [
                "CRC64NVME"
            ],
            "ChecksumType": "FULL_OBJECT",
            "Size": 240,
            "StorageClass": "STANDARD"
        }
    ],
    "RequestCharged": null,
    "Prefix": ""
}
```

## Server

### Help
```bash
Usage: dyndynser server <S3_ROBOCERTS_BUCKET> <DDNS_FILE_PATH> <S3_DDNS_JSON_DIR> <KEYS_SEARCH_PATH> <REGION>

Arguments:
  <S3_ROBOCERTS_BUCKET>
  <DDNS_FILE_PATH>
  <S3_DDNS_JSON_DIR>
  <KEYS_SEARCH_PATH>
  <REGION>

Options:
  -h, --help  Print help
```