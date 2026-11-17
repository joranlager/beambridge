# beambridge

A small Rust CLI that links two machines across the Internet, with **no port forwarding, firewall rules or router changes**
on either side. You pair the machines once with a short one-time code, then either forward TCP ports or join a
virtual LAN.

```
 pair once:        machine A:  beambridge pair            ->  code 37-48219305
                   machine B:  beambridge pair 37-48219305

 TCP tunnel:       A:  beambridge listen --to 127.0.0.1:22
                   B:  beambridge connect a --from 127.0.0.1:2222   ->  ssh -p 2222 127.0.0.1

 virtual LAN:      A and B (admin/root):  beambridge lan <peer>     ->  A=10.10.0.x  B=10.10.0.y  (ping, any port)
```

## How it works

- **Identity.** Each machine has a persistent key (`identity.key`); its public half is the machine's id.
- **Pairing = a shared secret number.** `beambridge pair` shows a code like `37-48219305`. The other machine enters it.
  The code is used as a password in a PAKE (SPAKE2, via [magic-wormhole](https://crates.io/crates/magic-wormhole)),
  and over the resulting encrypted channel the two machines swap public keys. Each saves the other in `peers.json`
  (trust on first use, like adding a PGP key). The code works **once**: a wrong guess burns it, so a short code is safe.
- **Connecting.** After pairing there are no codes or tokens. Connections use [iroh](https://iroh.computer): QUIC with
  NAT hole punching, and an encrypted relay fallback when a direct path is impossible (CGNAT, strict firewalls).
- **Access control.** A machine only accepts peers it has paired with. The peer's key is proven by the TLS handshake,
  and the allowlist is re-checked for every new stream, so `unpair` cuts off a live connection immediately.

## Build

Needs a recent stable Rust toolchain (on Windows, also the MSVC Build Tools).

```bash
cargo build --release
```

The binary is `target/release/beambridge` (`beambridge.exe` on Windows).

## Usage

### 1. Pair (once per pair of machines)

```bash
beambridge pair                 # machine A: prints a code and waits
beambridge pair 37-48219305     # machine B: enter the code
```

Both sides then trust each other. Use `--as NAME` to choose the name the other machine is stored under
(default: its hostname). `beambridge peers` lists paired machines, `beambridge unpair NAME` removes one,
and `beambridge id` shows this machine's id.

### 2a. TCP tunnel

```bash
beambridge listen --to 127.0.0.1:22              # machine with the service
beambridge connect <name> --from 127.0.0.1:2222  # machine that wants access
ssh -p 2222 user@127.0.0.1
```

Services that speak first (SSH, SMTP) and half-closing clients both work.

### 2b. Virtual LAN

Run the **same command on both machines**, with administrator/root rights:

```bash
beambridge lan <name>             # default network 10.10.0.x
beambridge lan <name> --net 10.77.5
```

The machine with the lower id becomes `<net>.1` and dials; the other becomes `<net>.2`. Both then see a normal
network adapter named `beambridge`: ping, file shares and any TCP/UDP port work. Choose a `--net` that does not
overlap your real LAN. The link reconnects automatically.

- **Windows:** run from an Administrator shell. Nothing else to install: the signed Wintun driver DLL
  ([wintun.net](https://www.wintun.net), WireGuard LLC) is built into `beambridge.exe` and is written to
  `%LOCALAPPDATA%\beambridge` on first use. Windows Firewall treats new adapters as *Public* and blocks incoming
  traffic (ping, file shares), so on **each machine, once**, allow the virtual LAN's addresses (admin PowerShell;
  use your own prefix if you changed `--net`):

  ```powershell
  New-NetFirewallRule -DisplayName "beambridge LAN" -Direction Inbound -RemoteAddress 10.10.0.0/24 -Action Allow
  ```

  The adapter exists only while `lan` is running (Windows removes it when the process exits), so commands that
  target the adapter by name, such as `Set-NetConnectionProfile -InterfaceAlias beambridge`, only work while `lan`
  is up and may have to be repeated each run. The rule above is permanent and does not depend on the adapter.
- **Linux/macOS:** run with `sudo`.

### Options

| Option | Applies to | Meaning |
|---|---|---|
| `--dir PATH` (env `BEAMBRIDGE_DIR`) | all | Where the key and peers are stored (default: your config directory) |
| `--as NAME` | `pair` | Name for the other machine |
| `--rendezvous URL` | `pair` | Use a different/self-hosted magic-wormhole mailbox server |
| `--to HOST:PORT` | `listen` | Local service to expose |
| `--from HOST:PORT` | `connect` | Local address to bind (default `127.0.0.1:2222`) |
| `--net A.B.C` | `lan` | Network prefix (default `10.10.0`) |

## Is it free? Is it anonymous?

**Free:** yes, with nothing to sign up for. It relies on public infrastructure run by others on a best-effort basis:

| Service | Used for | Alternative |
|---|---|---|
| magic-wormhole mailbox (`relay.magic-wormhole.io`) | pairing only | `--rendezvous` with your own server |
| n0 discovery and relay servers (iroh) | finding the peer; relaying when no direct path exists | iroh relays can be self-hosted (not wired into this CLI yet) |

If those services are down or change their terms, pairing or relayed connections can stop working; direct
connections between already-paired machines mostly depend on discovery.

**Anonymous: no.** The tunnel contents are end-to-end encrypted, and the services above cannot read them or your
pairing code. But they can see connection metadata: your IP address, the machines' public keys, and when they
connect. The peer you tunnel to also learns your IP when a direct connection is made (relayed connections hide it).
This tool gives you privacy of content and authenticated peers, not anonymity. Use Tor or a VPN on top if you need
that.

## Third-party code

The Windows build embeds the unmodified Wintun DLLs from `vendor/wintun/`, redistributed under WireGuard LLC's
[Prebuilt Binaries License](vendor/wintun/LICENSE.txt). Check that licence if you redistribute beambridge.

## Security notes

- Treat the pairing code like a password for the next minute or so: whoever enters it first becomes the paired
  peer. Share it over a channel you trust, and check that `pair` on your side reports success.
- Pairing is mutual: after it, each machine may use the other's `listen` service and `lan` link.
- `identity.key` is this machine's private key. Keep it private; anyone holding it can impersonate this machine.
- Bind `--from` to `127.0.0.1` unless you want other machines on your LAN to use the tunnel.

## Limitations

- IPv4 only for the virtual LAN; one peer per `lan` command.
- `lan` has not been tested between two real machines yet (it needs admin rights and two hosts); the pairing, TCP
  tunnel and allowlist have.
- No built-in support yet for self-hosted iroh relays.
