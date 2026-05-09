# Dyndynser
This program targets FreeBSD and Linux. Other platforms are not supported.

The purpose of this program is to securely request DDNS updates over Route53. The scope of this project is limited entirely to AWS EC2 instances which have a role for S3 buckets.

Dyndynser runs in two modes: Client Mode, and Server Mode.

Clients have a domain they are responsible for, get their current IP, write a `ddns.json` file with the information, sign the json with the domain's private key, and then push the signed object to s3.

Servers have the X509 certificates, which includes the CommonName and Public Key of the domain. They retrieve S3 objects, verify the signature of each item matches the key for the CommonName that they have certs for, and then updates Route53 with the successfully validated DNS requests.

In this setup, clients have no privilges for Route53, and only minimal put-only priveliges for S3.

The server is the only priveliged machine, having full S3 and Route 53 priveliges. 

This minimizes compromise surface. Additionally because the requests are signed, machines can only sign for the domain they are responible for, and cannot issue rogue requests for domains they do not own.


````mermaid
graph TD
    subgraph IAM["AWS IAM Roles"]
        iamClient["dyndns-client
        .
        s3:PutObject"]:::iamRole
        iamServer["dyndns-server
        .
        s3:GetObject
        s3:DeleteObject
        route53:ChangeResourceRecordSets"]:::iamRole
    end

    subgraph VPC
        sub1["sub1.domain.example
        client"]
        sub2["sub2.domain.example
        client"]
        dns["dns-gateway
        server"]
    end

    s3@{label: "S3 Bucket", shape: cylinder}
    r53@{label: "Route 53", shape: doc}

    classDef iamRole fill:#FFD700,stroke:#FF8C00,color:#000

    iamClient -. assumed by .-> sub1
    iamClient -. assumed by .-> sub2
    iamServer -. assumed by .-> dns

    sub1 -->|"cron dyndynser client
    🔑
    Write sub1.domain.example.ddns.json"| s3

    sub2 -->|"cron dyndynser client
    🔑
    Write sub2.domain.example.ddns.json"| s3

    dns <-->|"cron dyndynser server
    ✅ Validate JSON
    Read / Delete *.ddns.json"| s3

    dns -->|"ChangeResourceRecordSets"| r53

````

# Requirements

## Buiding

* Rust 1.70+
  
```
cargo build
```

## AWS Requirements
* Writeable S3 bucket to store ddns request info

### Runtime / Environment Requirements

### Both
* Running on an AWS EC2 instance

### Client
* Permissions: 
  * EC2 Instance Role with IAM priveldges for `s3:write` to your bucket of choice
* Firewall:
  * Ability to query `https://checkip.amazonaws.com` for an ip
* An ED25519 _Private_ Key for the domain to sign for, derived from an X.509 Certificate
  * formats include: `openssh`, and `ssh-keygen`, either is fine
  * password optional


### Server
* Permissions: 
  * EC2 Instance Role with IAM priveliges for `s3:read` from your bucket of choice
  * EC2 Instance Role with IAM privelides for `route53:read,write` to your main domain 
* An X.509 Certificate with a `CN` equal to the FQDN of the domain to update, and Key Usages of `Digital Signature`, `Non Repudiation`.


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

2. Move the Certificate to the Server's `/etc/dyndynser/knownkeys/` directory
    ```bash
    mv sub.domain.example.crt /etc/dyndynser/knownkeys/
    ```
3. Move the private key to any safe space on the Client EC2 instance, for instance, the `/etc/dyndynser/owneddomains/` directory:
    ```bash
    mv sub.domain.example.priv /etc/dyndynser/owneddomains/
    ```

## Client

Optional: Create a ddns client directory:

```bash
sudo mkdir -p /etc/dyndynser/owneddomains
sudo chmod +rw -R /etc/dyndynser
```


Assume the following environment variables: `signingkey=/etc/dyndynser/owneddomains/sub.domain.example.priv`, `region=us-east-1`, `s3bucket=somebucket`, `domain=sub.domain.example`, `s3path=/ddns/domains` and assume that the key is _not_ password protected:

### Help:
```bash
dyndynser client --help

Run in client mode, publishing a signed DDNS update request to S3 for the server to process. The update is cryptographically signed using the provided private key so the server can verify authenticity

Usage: dyndynser client [OPTIONS] --bucket <S3_BUCKET> --bucket-ddns-dir <S3_DDNS_JSON_DIR> --domain <DOMAIN> --key-path <KEY_PATH> --aws-region <AWS_REGION>

Options:
      --dry-run
          Simulate all operations without writing any DNS changes to S3. Will print what would otherwise be updated.
      --bucket <S3_BUCKET>
          S3 bucket name used as the DDNS backend
      --bucket-ddns-dir <S3_DDNS_JSON_DIR>
          S3 key prefix (directory) for pending DDNS update JSON files
      --domain <DOMAIN>
          Fully-qualified domain name to update (e.g. home.example.com)
      --ttl <TTL>
          DNS record TTL in seconds (uses server default if omitted)
      --key-path <KEY_PATH>
          Path to the PEM-encoded Ed25519 private key file for signing
      --signing-key-password <SIGNING_KEY_PASSWORD>
          Passphrase to decrypt the private key (omit if the key is not encrypted) [env: DYNDYNSER_SIGNING_KEY_PASSWORD=]
      --aws-region <AWS_REGION>
          AWS region of the S3 bucket (e.g. eu-west-1) [env: DYNDYNSER_AWS_REGION=]
      --ip-addr-check-url <IP_ADDR_CHECK_URL>
          URL of service to use to check IP Address. Must return a bare ip-address in either v4 or v6
  -h, --help
          Print help
```

### Dry Run, test what will be written:
```bash
dyndynser client --dry-run --bucket $s3bucket --bucket-ddns-dir $s3path --key-path $signingkey --aws-region $region
Will write to: s3://somebucket/ddns/domains/sub.example.com.ddns.json
JSON:
{
  "payload": {
    "domain": "sub.domain.example",
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
            "Key": "ddns/domains/sub.domain.example.ddns.json",
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

The server side is architected such that many errors are non-blocking. The only things that are show-stoppers are if S3 or Route53 can't be contacted.
Other errors, such as malformed JSON ddns requests, malformed keys, or mismatched signatures, only cause those errors to be reported, but do not terminate the program.

This is so that invalid configurations by the client can't DOS the service, and records will continue to be updated.

Optional: Create a ddns server directory:

```bash
sudo mkdir -p /etc/dyndynser/knownkeys
sudo chmod +rw -R /etc/dyndynser
```

### Help
```bash
dyndynser server --help

Run in server mode, processing and validating DDNS update requests stored in S3. The server verifies cryptographic signatures on each request against a set of trusted public keys before applying any DNS record changes

Usage: dyndynser server [OPTIONS] --bucket <S3_BUCKET> --bucket-ddns-dir <S3_DDNS_JSON_DIR> --hosted-zone-id <HOSTED_DNS_ZONE_ID> --keys-search-path <KEYS_SEARCH_PATH> --aws-region <AWS_REGION>

Options:
      --dry-run
          Simulate all operations without writing any DNS changes to Route53. Will print what would otherwise be updated.
      --bucket <S3_BUCKET>
          S3 bucket name used as the DDNS backend
      --bucket-ddns-dir <S3_DDNS_JSON_DIR>
          S3 key prefix (directory) for pending DDNS update JSON files
      --hosted-zone-id <HOSTED_DNS_ZONE_ID>
          Id of the Local Hosted DNS Zone [env: DYNDYNSER_AWS_HOSTED_ZONE_ID=]
      --keys-search-path <KEYS_SEARCH_PATH>
          Directory to search for trusted public key files used in signature verification
      --aws-region <AWS_REGION>
          AWS region of the S3 bucket (e.g. eu-west-1) [env: DYNDYNSER_AWS_REGION=]
      --max-signed-at-time-ago <MAX_TIME_AGO_SIGNED_AT_SECS>
          Maximum seconds in the past that a ddns request can be signed at before being rejected for being stale
  -h, --help
          Print help
```


# Design and Architecture

This binary is built for both Linux and FreeBSD.

It assumed a Privelige Dropping role, due to the Private Key material involved. After reading the necessary keys, it drops privs down to the minimal set.
But it only does this opportunitsically. if the process is not root and the reads succeed, then privs are not dropped. If the reads don't succeed, the program tells you to run as root to read those keys. If the program _is_ root, then it drops privs after reading successfully.

# Packaging
Creates a `dyndynser` user and `dynsynser` group. Dyndynser user is put into the group.
Creates `/etc/dyndynser`, with `770`, and ownership of `root:dyndynser`, such that the program can read its own configuration, but cannot write it, following the pattern set by `/etc/shadow`.