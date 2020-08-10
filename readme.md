# Open source high performance cjdns Route Server

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

### Individual crates

[**cjdns-entities**](cjdns-entities/) - entities operated by CJDNS.

[**cjdns-splice**](cjdns-splice/) - tools for manipulating and splicing cjdns routing labels.

[**cjdns-encode**](cjdns-encode/) - serializing/deserializing of encoding schemes.

[**cjdns-keys**](cjdns-keys/) - public & private keys.

## Development

Formatting code:

```bash
cargo fmt
```
