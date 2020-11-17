# Open source high performance cjdns Route Server

[![Build Status](https://travis-ci.org/CJDNS-Development-Team/CJDNS.svg?branch=master)](https://travis-ci.org/CJDNS-Development-Team/CJDNS)

## Build & test

Debug build:

```bash
cargo test
```

Release build:

```bash
cargo build --release
```

## Docs
To build docs yourself use command:
```bash
cargo doc --no-deps
```
To read docs online visit https://cjdns-development-team.github.io/docs/

### Individual crates

[**cjdns-admin**](cjdns-admin/) - Admin API connector for talking to CJDNS engine

[**cjdns-ann**](cjdns-ann/) - Library for parsing CJDNS route announcement messages.

[**cjdns-bencode**](cjdns-bencode/) - Wrapper over Bendy library implementing *bencode* format.

[**cjdns-bytes**](cjdns-bytes/) - Utilities for parsing and serializing messages.

[**cjdns-core**](cjdns-core/) - Core CJDNS types and algorithms:
- routing labels;
- tools for manipulating and splicing CJDNS routing labels;
- serializing/deserializing of encoding schemes.

[**cjdns-ctrl**](cjdns-ctrl/) - Tools for parsing/serializing CTRL messages.

[**cjdns-hdr**](cjdns-hdr/) - Library for parsing and serializing CJDNS route and data headers.

[**cjdns-keys**](cjdns-keys/) - Tools for working with CJDNS keys:
- IPv6 addresses;
- public & private keys.

[**cjdns-sniff**](cjdns-sniff/) - Library for sniffing and injecting CJDNS traffic.

[**cjdns-snode**](cjdns-snode/) - The cjdns supernode.

[**netchecksum**](netchecksum/) - This is an ultra-simple library which implements the 1's complement checksum used by TCP, UDP and ICMP.

## Development

Formatting code:

```bash
cargo fmt
```
