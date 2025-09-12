# Talaria

Talaria is a (very early) WIP all-in-one email server


## Goals

- Full IMAP4rev2 (RFC 9051), SMTP (RFC 5321), and mail submission (RFC 6409) support
- Web interface for managing user accounts
- Flexible configuration that allows a single build to work as an originator, delivery, relay or gateway system (RFC5321 Section 2.3.10)


## Building from source

### Prerequisites

- (zig)[https://ziglang.org] v0.15.1

```bash
git clone https://github.com/Cameron-Reed1/talaria.git
cd talaria
zig build --fetch --release
```
