//! Pairing: two people share a short one-time code; a PAKE (magic-wormhole's SPAKE2)
//! derives a shared key from it, and over that authenticated channel the two machines
//! swap their long-term public keys. Each side then trusts the other from then on.
//!
//! The rendezvous (mailbox) server only relays PAKE messages and ciphertext. It never
//! learns the code, the keys, or anything about the later tunnel.

use crate::store::Store;
use anyhow::{Context, Result, bail};
use iroh::EndpointId;
use magic_wormhole::{AppConfig, AppID, Code, MailboxConnection, Password, Wormhole};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;

const APP_ID: &str = "beambridge.pairing/v1";

#[derive(Serialize, Deserialize)]
struct Hello {
    id: String,
    name: String,
}

fn config(rendezvous: &str) -> AppConfig<()> {
    AppConfig {
        id: AppID::new(APP_ID),
        rendezvous_url: Cow::Owned(rendezvous.to_string()),
        app_version: (),
    }
}

/// 8 random digits (about 26 bits). That is plenty because a code is single use: a wrong
/// guess burns it, so an attacker gets one online attempt, never an offline attack.
fn random_password() -> Result<Password> {
    for _ in 0..50 {
        let mut b = [0u8; 8];
        getrandom::fill(&mut b).map_err(|e| anyhow::anyhow!("random: {e}"))?;
        let n = u64::from_le_bytes(b) % 100_000_000;
        // Rejects trivially weak values such as 00000000 or 12345678.
        if let Ok(p) = format!("{n:08}").parse::<Password>() {
            return Ok(p);
        }
    }
    bail!("could not generate a strong pairing code")
}

fn local_name() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "peer".into())
}

/// Peer names end up in a file and on the command line: keep them boring.
fn sanitize(name: &str) -> String {
    let s: String = name
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        .take(32)
        .collect();
    if s.is_empty() { "peer".into() } else { s.to_lowercase() }
}

/// Start a pairing and wait for the other machine (`code` is None), or join one.
pub async fn run(
    store: &Store,
    my_id: EndpointId,
    code: Option<String>,
    label: Option<String>,
    rendezvous: &str,
) -> Result<()> {
    let mailbox = match code {
        None => {
            let mb = MailboxConnection::create_with_password(config(rendezvous), random_password()?)
                .await
                .context("contacting the rendezvous server")?;
            println!("Pairing code: {}", mb.code());
            println!("On the other machine run:  beambridge pair {}", mb.code());
            println!("Waiting for the other machine (the code works once)...");
            mb
        }
        Some(c) => {
            let code: Code = c.trim().parse().context("invalid pairing code")?;
            MailboxConnection::connect(config(rendezvous), code, false)
                .await
                .context("joining the pairing (wrong or already used code?)")?
        }
    };

    // The key exchange happens here; a wrong code makes this fail.
    let mut wh = Wormhole::connect(mailbox)
        .await
        .context("key exchange failed (wrong code, or someone interfered)")?;

    wh.send_json(&Hello { id: my_id.to_string(), name: local_name() }).await?;
    let theirs: Hello = wh.receive_json().await??;
    let their_id: EndpointId = theirs.id.parse().context("peer sent an invalid id")?;
    if their_id == my_id {
        bail!("you paired this machine with itself");
    }
    let wanted = label.map(|l| sanitize(&l)).unwrap_or_else(|| sanitize(&theirs.name));
    let stored = store.add_peer(&wanted, their_id)?;
    wh.close().await.ok();

    println!("Paired with '{stored}' ({their_id}).");
    Ok(())
}
