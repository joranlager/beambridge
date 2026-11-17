# beambridge

A small Rust CLI that tunnels a TCP port between two machines across the Internet.
No port forwarding, firewall rules or router changes are needed on either side.

```
 machine B                                   machine A
 your client ──► 127.0.0.1:2222              127.0.0.1:22 ◄── sshd (or any TCP service)
                      │                              ▲
                  beambridge connect ◄── QUIC ──► beambridge listen
```

## How it works

beambridge is built on [iroh](https://iroh.computer):

- Each peer has a public key, which serves as its address (the **Tunnel ID**). There are no IPs to share.
- The two peers find each other through n0's public discovery services, then try to open a direct
  QUIC connection by **NAT hole punching**.
- If a direct path is impossible (strict firewalls, CGNAT), traffic falls back to an encrypted
  **relay** server. The relay cannot read the traffic.
- The connection is encrypted and each side verifies the other's key.
- Every tunneled TCP connection becomes its own bidirectional QUIC stream over a single connection.

## Build

Requires a recent stable Rust toolchain (on Windows, also the MSVC Build Tools).

```bash
cargo build --release
```

The binary is `target/release/beambridge` (`beambridge.exe` on Windows).

## Usage

### 1. On the machine that has the service (A)

```bash
beambridge listen --to 127.0.0.1:22
```

It prints a Tunnel ID and the command to run on the other side:

```
Tunnel ID: 965946f9...54a218
Forwarding to 127.0.0.1:22. On the other machine run:
  beambridge connect 965946f9...54a218 --from 127.0.0.1:2222
```

### 2. On the machine that wants access (B)

```bash
beambridge connect <TUNNEL_ID> --from 127.0.0.1:2222
```

Anything that connects to `127.0.0.1:2222` on B now reaches `127.0.0.1:22` on A:

```bash
ssh -p 2222 user@127.0.0.1
```

### Commands

| Command | Option | Description |
|---|---|---|
| `listen` | `--to <host:port>` | Local TCP service to expose (required) |
| `connect <ID>` | `--from <host:port>` | Local address to bind (default `127.0.0.1:2222`) |

Run `beambridge --help` for details. Messages go to stderr; the ID and status lines go to stdout.

## Example: quick test on one machine

```bash
python -m http.server 8000 --bind 127.0.0.1     # the service
beambridge listen --to 127.0.0.1:8000           # note the ID
beambridge connect <ID> --from 127.0.0.1:2222   # in another terminal
curl http://127.0.0.1:2222/
```

## Security notes

- **Anyone who knows the Tunnel ID can connect to the listener.** Treat the ID like a password and
  share it only over a trusted channel. There is no peer allowlist yet.
- The Tunnel ID changes on every `listen` run, because the key is generated fresh each time.
- Bind `--from` to `127.0.0.1` unless you intend to expose the tunnel to your LAN.
- By default, discovery and relaying use n0's public infrastructure. Connection metadata (peer IDs,
  IP addresses during hole punching) is visible to those services; tunnel contents are not.

## Limitations and ideas

- TCP only; UDP and full VPN (TUN device) support are not implemented.
- Persistent identity key and an allowlist of authorized peer IDs.
- Self-hosted relay and discovery option.
- One service per `listen`; multiple port mappings would be a natural extension.
