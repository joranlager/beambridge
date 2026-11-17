//! Virtual LAN: a TUN network adapter on each machine, IP packets carried as QUIC
//! datagrams over the same authenticated iroh connection. Run the same command on
//! both machines; the one with the lower id gets `<net>.1` and dials, the other gets
//! `<net>.2` and accepts.
//!
//! Needs administrator/root rights. On Windows `wintun.dll` must sit next to the exe.

use crate::{Endpoint, EndpointId};
use anyhow::{Context, Result, bail};
use bytes::Bytes;
use iroh::endpoint::{Connection, SendDatagramError};
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;
use tun_rs::{AsyncDevice, DeviceBuilder};

pub const ALPN: &[u8] = b"beambridge/lan/0";
/// Small enough to fit one QUIC datagram on any path, including the relay.
const MTU: u16 = 1000;

pub async fn run(endpoint: Endpoint, peer: EndpointId, net: &str) -> Result<()> {
    let parts: Vec<u8> = net
        .split('.')
        .map(|p| p.parse::<u8>())
        .collect::<Result<_, _>>()
        .context("--net must look like 10.10.0")?;
    if parts.len() != 3 {
        bail!("--net must be three numbers, like 10.10.0");
    }
    let me = endpoint.id();
    let dialer = me.to_string() < peer.to_string();
    let host = if dialer { 1 } else { 2 };
    let my_ip = Ipv4Addr::new(parts[0], parts[1], parts[2], host);
    let peer_ip = Ipv4Addr::new(parts[0], parts[1], parts[2], 3 - host);

    let dev = DeviceBuilder::new()
        .name("beambridge")
        .mtu(MTU)
        .ipv4(my_ip, 24, None)
        .build_async()
        .map_err(|e| {
            let hint = if cfg!(windows) {
                "Run as Administrator and put wintun.dll (from wintun.net) next to beambridge.exe."
            } else {
                "Run as root (or grant CAP_NET_ADMIN)."
            };
            anyhow::anyhow!("creating the network adapter failed: {e}. {hint}")
        })?;
    let dev = Arc::new(dev);
    println!("Virtual LAN up: this machine is {my_ip}; the peer will be {peer_ip}.");
    println!("Waiting for the peer to connect...");

    loop {
        let conn = if dialer { dial(&endpoint, peer).await } else { accept(&endpoint, peer).await? };
        println!("Connected to peer: {peer_ip} is reachable.");
        match pump(&dev, &conn).await {
            Ok(()) => {}
            Err(e) => eprintln!("link lost: {e:#}"),
        }
        eprintln!("Reconnecting...");
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

async fn dial(endpoint: &Endpoint, peer: EndpointId) -> Connection {
    loop {
        match endpoint.connect(peer, ALPN).await {
            Ok(c) => return c,
            Err(_) => tokio::time::sleep(Duration::from_secs(3)).await,
        }
    }
}

async fn accept(endpoint: &Endpoint, peer: EndpointId) -> Result<Connection> {
    loop {
        let Some(incoming) = endpoint.accept().await else {
            bail!("endpoint closed");
        };
        let Ok(conn) = incoming.await else { continue };
        if conn.remote_id() == peer {
            return Ok(conn);
        }
        conn.close(1u32.into(), b"not the expected peer");
    }
}

async fn pump(dev: &AsyncDevice, conn: &Connection) -> Result<()> {
    let to_peer = async {
        let mut buf = vec![0u8; 65535];
        let mut warned = false;
        loop {
            let n = dev.recv(&mut buf).await?;
            match conn.send_datagram(Bytes::copy_from_slice(&buf[..n])) {
                Ok(()) => {}
                Err(SendDatagramError::TooLarge) => {
                    if !warned {
                        eprintln!("dropping a packet larger than the tunnel MTU ({MTU})");
                        warned = true;
                    }
                }
                Err(e) => return Err::<(), anyhow::Error>(e.into()),
            }
        }
    };
    let from_peer = async {
        loop {
            let d = conn.read_datagram().await?;
            dev.send(&d).await?;
        }
        #[allow(unreachable_code)]
        Ok::<(), anyhow::Error>(())
    };
    tokio::select! { r = to_peer => r, r = from_peer => r }
}
