//! Virtual LAN: a TUN network adapter on each machine, IP packets carried as QUIC
//! datagrams over the same authenticated iroh connection. Run the same command on
//! both machines; the one with the lower id gets `<net>.1` and dials, the other gets
//! `<net>.2` and accepts.
//!
//! Needs administrator/root rights. On Windows the Wintun driver DLL is embedded in the exe.

use crate::{Endpoint, EndpointId};
use anyhow::{Context, Result, bail};
use bytes::Bytes;
use iroh::endpoint::{Connection, SendDatagramError};
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;
use tun_rs::{AsyncDevice, DeviceBuilder};

pub const ALPN: &[u8] = b"beambridge/lan/0";
/// Initial adapter MTU, small enough for any path; adjusted to the real path once connected.
const MTU: u16 = 1000;
/// Bounds for the adapter MTU (IPv4 needs at least 576).
const MTU_MIN: u16 = 576;
const MTU_MAX: u16 = 1400;

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

    let builder = DeviceBuilder::new().name("beambridge").ipv4(my_ip, 24, None);
    // Windows: `mtu()` would also set the IPv6 MTU, and values below 1280 are invalid for IPv6
    // (OS error 87). The LAN is IPv4 only, so set just the IPv4 MTU.
    #[cfg(windows)]
    let builder = builder.mtu_v4(MTU);
    #[cfg(not(windows))]
    let builder = builder.mtu(MTU);
    // Windows: the Wintun driver DLL is embedded in the exe; keep it locked while we run.
    #[cfg(windows)]
    let (builder, _wintun) = {
        let w = crate::wintun::extract()?;
        (builder.wintun_file(w.path.clone()), w)
    };
    let dev = builder.build_async().map_err(|e| {
        // Only suggest elevation when the OS actually refused for lack of rights.
        let denied = e.kind() == std::io::ErrorKind::PermissionDenied || e.raw_os_error() == Some(1314);
        let hint = match (denied, cfg!(windows)) {
            (true, true) => " Run from an Administrator shell.",
            (true, false) => " Run as root (or grant CAP_NET_ADMIN).",
            (false, _) => "",
        };
        anyhow::anyhow!("creating the network adapter failed: {e}.{hint}")
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

/// The adapter MTU follows what the connection can actually carry in one QUIC datagram. That
/// depends on the network path (direct or relay) and can change while connected.
fn path_mtu(conn: &Connection) -> Option<u16> {
    conn.max_datagram_size().map(|m| m.clamp(MTU_MIN as usize, MTU_MAX as usize) as u16)
}

async fn pump(dev: &AsyncDevice, conn: &Connection) -> Result<()> {
    let Some(first) = path_mtu(conn) else {
        bail!("the peer does not support datagrams (is it running the same beambridge version?)");
    };
    dev.set_mtu(first).context("setting the adapter MTU")?;
    println!("Adapter MTU set to {first} (what this network path carries).");

    let to_peer = async {
        let mut buf = vec![0u8; 65535];
        let mut warned = false;
        loop {
            let n = dev.recv(&mut buf).await?;
            match conn.send_datagram(Bytes::copy_from_slice(&buf[..n])) {
                Ok(()) => {}
                Err(SendDatagramError::TooLarge) => {
                    // The watcher below lowers the MTU shortly; TCP retransmits smaller segments.
                    if !warned {
                        eprintln!(
                            "dropped a {n}-byte packet: this path carries at most {:?} bytes; adjusting the MTU",
                            conn.max_datagram_size()
                        );
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
    // Re-check the path every few seconds (a relay path becoming direct raises the limit,
    // the reverse lowers it).
    let watch = async {
        let mut cur = first;
        loop {
            tokio::time::sleep(Duration::from_secs(3)).await;
            if let Some(m) = path_mtu(conn)
                && m != cur
            {
                dev.set_mtu(m).context("updating the adapter MTU")?;
                println!("Adapter MTU changed {cur} -> {m} (network path changed).");
                cur = m;
            }
        }
        #[allow(unreachable_code)]
        Ok::<(), anyhow::Error>(())
    };
    tokio::select! { r = to_peer => r, r = from_peer => r, r = watch => r }
}
