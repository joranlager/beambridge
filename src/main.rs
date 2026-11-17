//! beambridge: TCP tunnel between two machines over the Internet, no port forwarding.
//!
//! Built on iroh: QUIC + NAT hole punching, with an encrypted relay fallback when
//! a direct path is impossible. Peers are addressed by public key, and the QUIC
//! connection is mutually authenticated by that key.
//!
//!   machine A (has the service):  beambridge listen --to 127.0.0.1:22
//!   machine B (wants access):     beambridge connect <ID> --from 127.0.0.1:2222

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use iroh::{Endpoint, EndpointId};
use tokio::net::{TcpListener, TcpStream};

const ALPN: &[u8] = b"beambridge/tunnel/0";

#[derive(Parser)]
#[command(version, about)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Expose a local TCP service to a remote peer.
    Listen {
        /// Local service to forward to, e.g. 127.0.0.1:22
        #[arg(long)]
        to: String,
    },
    /// Open a local port that tunnels to the remote listener's service.
    Connect {
        /// ID printed by `listen`
        id: String,
        /// Local address to bind, e.g. 127.0.0.1:2222
        #[arg(long, default_value = "127.0.0.1:2222")]
        from: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Listen { to } => listen(to).await,
        Cmd::Connect { id, from } => connect(id, from).await,
    }
}

async fn listen(target: String) -> Result<()> {
    let endpoint = Endpoint::builder(iroh::endpoint::presets::N0).alpns(vec![ALPN.to_vec()]).bind().await?;
    endpoint.online().await;
    println!("Tunnel ID: {}", endpoint.id());
    println!("Forwarding to {target}. On the other machine run:");
    println!("  beambridge connect {} --from 127.0.0.1:2222", endpoint.id());

    while let Some(incoming) = endpoint.accept().await {
        let target = target.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_peer(incoming, target).await {
                eprintln!("peer error: {e:#}");
            }
        });
    }
    Ok(())
}

async fn handle_peer(incoming: iroh::endpoint::Incoming, target: String) -> Result<()> {
    let conn = incoming.await?;
    eprintln!("peer connected: {}", conn.remote_id());
    // Each tunneled TCP connection is one bidirectional QUIC stream.
    loop {
        let (mut send, mut recv) = conn.accept_bi().await?;
        let target = target.clone();
        tokio::spawn(async move {
            let res: Result<()> = async {
                let mut tcp = TcpStream::connect(&target).await.context("connect target")?;
                let (mut r, mut w) = tcp.split();
                let up = tokio::io::copy(&mut recv, &mut w);
                let down = tokio::io::copy(&mut r, &mut send);
                tokio::select! { a = up => { a?; } b = down => { b?; } }
                let _ = send.finish();
                Ok(())
            }
            .await;
            if let Err(e) = res {
                eprintln!("stream error: {e:#}");
            }
        });
    }
}

async fn connect(id: String, from: String) -> Result<()> {
    let remote: EndpointId = id.parse().context("invalid ID")?;
    let endpoint = Endpoint::builder(iroh::endpoint::presets::N0).bind().await?;
    let conn = endpoint.connect(remote, ALPN).await.context("connecting to peer")?;
    eprintln!("connected to {remote}");

    let listener = TcpListener::bind(&from).await.context("bind local port")?;
    println!("Listening on {from}; traffic is tunneled to the remote service.");
    loop {
        let (mut tcp, addr) = listener.accept().await?;
        let conn = conn.clone();
        tokio::spawn(async move {
            let res: Result<()> = async {
                let (mut send, mut recv) = conn.open_bi().await?;
                let (mut r, mut w) = tcp.split();
                let up = tokio::io::copy(&mut r, &mut send);
                let down = tokio::io::copy(&mut recv, &mut w);
                tokio::select! { a = up => { a?; } b = down => { b?; } }
                let _ = send.finish();
                Ok(())
            }
            .await;
            if let Err(e) = res {
                eprintln!("{addr}: {e:#}");
            }
        });
    }
}
