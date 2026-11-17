//! beambridge: tunnel between two machines over the Internet, no port forwarding.
//!
//! Built on iroh (QUIC, NAT hole punching, encrypted relay fallback). Machines are
//! identified by a persistent key and trust each other only after `beambridge pair`.

mod lan;
mod pair;
mod store;
#[cfg(windows)]
mod wintun;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use iroh::endpoint::{Connection, Incoming, RecvStream, SendStream};
use iroh::{Endpoint, EndpointId};
use std::path::PathBuf;
use store::Store;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};

const TCP_ALPN: &[u8] = b"beambridge/tcp/0";

#[derive(Parser)]
#[command(version, about)]
struct Cli {
    /// Where the identity key and paired peers are stored
    #[arg(long, global = true, env = "BEAMBRIDGE_DIR")]
    dir: Option<PathBuf>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Show this machine's id.
    Id,
    /// Pair with another machine using a one-time code. Without CODE, create one and wait.
    Pair {
        /// Code shown by the other machine, e.g. 37-48219305
        code: Option<String>,
        /// Name to store the other machine under (default: its hostname)
        #[arg(long = "as")]
        label: Option<String>,
        /// Rendezvous (mailbox) server; only PAKE messages and ciphertext pass through it
        #[arg(long, default_value = magic_wormhole::rendezvous::DEFAULT_RENDEZVOUS_SERVER)]
        rendezvous: String,
    },
    /// List paired machines.
    Peers,
    /// Forget a paired machine.
    Unpair { name: String },
    /// Expose a local TCP service to paired machines.
    Listen {
        /// Local service to forward to, e.g. 127.0.0.1:22
        #[arg(long)]
        to: String,
    },
    /// Open a local port that tunnels to a paired machine's `listen` service.
    Connect {
        /// Paired peer name
        peer: String,
        /// Local address to bind
        #[arg(long, default_value = "127.0.0.1:2222")]
        from: String,
    },
    /// Join a virtual LAN with a paired machine (run on both machines; needs admin/root).
    Lan {
        /// Paired peer name
        peer: String,
        /// Three-octet network prefix; the two machines become .1 and .2
        #[arg(long, default_value = "10.10.0")]
        net: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let store = Store::open(cli.dir)?;
    match cli.cmd {
        Cmd::Id => {
            println!("{}", store.secret_key()?.public());
            Ok(())
        }
        Cmd::Pair { code, label, rendezvous } => {
            pair::run(&store, store.secret_key()?.public(), code, label, &rendezvous).await
        }
        Cmd::Peers => {
            let peers = store.peers()?;
            if peers.is_empty() {
                println!("No paired machines. Use `beambridge pair`.");
            }
            for (name, id) in peers {
                println!("{name}\t{id}");
            }
            Ok(())
        }
        Cmd::Unpair { name } => {
            if store.remove_peer(&name)? {
                println!("Removed '{name}'.");
                Ok(())
            } else {
                anyhow::bail!("no paired peer named '{name}'")
            }
        }
        Cmd::Listen { to } => listen(&store, to).await,
        Cmd::Connect { peer, from } => {
            let id = store.resolve(&peer)?;
            connect(&store, id, from).await
        }
        Cmd::Lan { peer, net } => {
            let id = store.resolve(&peer)?;
            let ep = endpoint(&store, lan::ALPN).await?;
            lan::run(ep, id, &net).await
        }
    }
}

async fn endpoint(store: &Store, alpn: &[u8]) -> Result<Endpoint> {
    Ok(Endpoint::builder(iroh::endpoint::presets::N0)
        .secret_key(store.secret_key()?)
        .alpns(vec![alpn.to_vec()])
        .bind()
        .await?)
}

/// Copy both directions with correct half-close handling, so a protocol that closes one
/// direction (for example a client that finishes sending) still gets the rest of the reply.
async fn pump(tcp: TcpStream, mut send: SendStream, mut recv: RecvStream) -> Result<()> {
    let (mut tr, mut tw) = tcp.into_split();
    let up = async {
        tokio::io::copy(&mut tr, &mut send).await?;
        send.finish()?;
        anyhow::Ok(())
    };
    let down = async {
        tokio::io::copy(&mut recv, &mut tw).await?;
        tw.shutdown().await?;
        anyhow::Ok(())
    };
    tokio::try_join!(up, down)?;
    Ok(())
}

async fn listen(store: &Store, target: String) -> Result<()> {
    let paired = store.peers()?;
    if paired.is_empty() {
        anyhow::bail!("no paired machines yet: run `beambridge pair` first");
    }
    let ep = endpoint(store, TCP_ALPN).await?;
    ep.online().await;
    println!("Forwarding paired machines to {target}. Allowed peers:");
    for (name, _) in &paired {
        println!("  {name}");
    }
    println!("On the other machine: beambridge connect <name>");

    let dir_store = std::sync::Arc::new(store.clone());
    while let Some(incoming) = ep.accept().await {
        let (target, st) = (target.clone(), dir_store.clone());
        tokio::spawn(async move {
            if let Err(e) = handle_peer(incoming, target, st).await {
                eprintln!("peer error: {e:#}");
            }
        });
    }
    Ok(())
}

async fn handle_peer(incoming: Incoming, target: String, store: std::sync::Arc<Store>) -> Result<()> {
    let conn = incoming.await?;
    let remote = conn.remote_id();
    // The id is proven by the TLS handshake, so this is real authentication.
    let Some(name) = store.name_of(&remote)? else {
        eprintln!("rejected unpaired peer {remote}");
        conn.close(1u32.into(), b"not paired");
        return Ok(());
    };
    eprintln!("peer connected: {name}");
    loop {
        let (send, mut recv) = match conn.accept_bi().await {
            Ok(s) => s,
            Err(_) => {
                eprintln!("peer disconnected: {name}");
                return Ok(());
            }
        };
        // Re-check on every stream so `unpair` cuts off an already-open connection.
        if store.name_of(&remote)?.is_none() {
            eprintln!("peer {name} was unpaired; closing its connection");
            conn.close(1u32.into(), b"unpaired");
            return Ok(());
        }
        let target = target.clone();
        tokio::spawn(async move {
            let res: Result<()> = async {
                // The opener sends one byte so the stream is announced even when the
                // service speaks first (SSH, SMTP...).
                let mut hello = [0u8; 1];
                recv.read_exact(&mut hello).await.context("stream header")?;
                let tcp = TcpStream::connect(&target).await.context("connect target")?;
                pump(tcp, send, recv).await
            }
            .await;
            if let Err(e) = res {
                eprintln!("stream error: {e:#}");
            }
        });
    }
}

async fn connect(store: &Store, remote: EndpointId, from: String) -> Result<()> {
    let ep = endpoint(store, TCP_ALPN).await?;
    let conn = ep.connect(remote, TCP_ALPN).await.context("connecting to peer (is `listen` running there?)")?;
    eprintln!("connected to {remote}");

    let listener = TcpListener::bind(&from).await.context("bind local port")?;
    println!("Listening on {from}; traffic is tunneled to the remote service.");
    loop {
        let (tcp, addr) = listener.accept().await?;
        let conn: Connection = conn.clone();
        tokio::spawn(async move {
            let res: Result<()> = async {
                let (mut send, recv) = conn.open_bi().await?;
                send.write_all(&[0u8]).await?;
                pump(tcp, send, recv).await
            }
            .await;
            if let Err(e) = res {
                eprintln!("{addr}: {e:#}");
            }
        });
    }
}
