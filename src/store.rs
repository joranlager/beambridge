//! Persistent identity key and the list of paired (trusted) peers.

use anyhow::{Context, Result, bail};
use iroh::{EndpointId, SecretKey};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::{ErrorKind, Write};
use std::path::PathBuf;

#[derive(Clone)]
pub struct Store {
    dir: PathBuf,
}

#[derive(Serialize, Deserialize, Default)]
struct PeersFile {
    /// name -> endpoint id (string form)
    peers: BTreeMap<String, String>,
}

impl Store {
    pub fn open(dir: Option<PathBuf>) -> Result<Self> {
        let dir = match dir {
            Some(d) => d,
            None => dirs::config_dir()
                .context("could not determine the config directory; pass --dir")?
                .join("beambridge"),
        };
        std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
        Ok(Self { dir })
    }

    /// Load this machine's identity key, creating it on first use.
    pub fn secret_key(&self) -> Result<SecretKey> {
        let path = self.dir.join("identity.key");
        loop {
            match std::fs::read_to_string(&path) {
                Ok(s) => {
                    let bytes = hex_decode(s.trim()).context("identity.key is corrupt")?;
                    return Ok(SecretKey::from_bytes(&bytes));
                }
                Err(e) if e.kind() == ErrorKind::NotFound => {
                    let key = SecretKey::generate();
                    match write_new_private(&path, &hex_encode(&key.to_bytes())) {
                        Ok(()) => return Ok(key),
                        // Another process created it first: read theirs.
                        Err(e) if e.kind() == ErrorKind::AlreadyExists => continue,
                        Err(e) => return Err(e).context("writing identity.key"),
                    }
                }
                Err(e) => return Err(e).context("reading identity.key"),
            }
        }
    }

    fn peers_path(&self) -> PathBuf {
        self.dir.join("peers.json")
    }

    fn load(&self) -> Result<PeersFile> {
        match std::fs::read_to_string(self.peers_path()) {
            Ok(s) => serde_json::from_str(&s).context("peers.json is corrupt"),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(PeersFile::default()),
            Err(e) => Err(e).context("reading peers.json"),
        }
    }

    fn save(&self, f: &PeersFile) -> Result<()> {
        let tmp = self.dir.join("peers.json.tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(f)?)?;
        std::fs::rename(&tmp, self.peers_path())?;
        Ok(())
    }

    /// All paired peers as (name, id).
    pub fn peers(&self) -> Result<Vec<(String, EndpointId)>> {
        self.load()?
            .peers
            .into_iter()
            .map(|(n, id)| Ok((n, id.parse::<EndpointId>().context("bad id in peers.json")?)))
            .collect()
    }

    /// Name under which `id` is paired, if any. Re-reads the file each call so a
    /// pairing done while `listen` is running takes effect immediately.
    pub fn name_of(&self, id: &EndpointId) -> Result<Option<String>> {
        let want = id.to_string();
        Ok(self.load()?.peers.into_iter().find(|(_, v)| *v == want).map(|(n, _)| n))
    }

    /// Trust `id`. Returns the name it was stored under (made unique if needed).
    pub fn add_peer(&self, desired: &str, id: EndpointId) -> Result<String> {
        let mut f = self.load()?;
        let idstr = id.to_string();
        f.peers.retain(|_, v| *v != idstr); // re-pairing replaces the old entry
        let mut name = desired.to_string();
        let mut n = 2;
        while f.peers.contains_key(&name) {
            name = format!("{desired}-{n}");
            n += 1;
        }
        f.peers.insert(name.clone(), idstr);
        self.save(&f)?;
        Ok(name)
    }

    pub fn remove_peer(&self, name: &str) -> Result<bool> {
        let mut f = self.load()?;
        let existed = f.peers.remove(name).is_some();
        if existed {
            self.save(&f)?;
        }
        Ok(existed)
    }

    /// Resolve a peer name (or a full id) to a *paired* peer's id.
    pub fn resolve(&self, s: &str) -> Result<EndpointId> {
        let f = self.load()?;
        if let Some(id) = f.peers.get(s) {
            return id.parse().context("bad id in peers.json");
        }
        if let Ok(id) = s.parse::<EndpointId>()
            && f.peers.values().any(|v| *v == id.to_string())
        {
            return Ok(id);
        }
        bail!("'{s}' is not a paired peer. Pair first with `beambridge pair` (see `beambridge peers`).")
    }
}

fn write_new_private(path: &std::path::Path, contents: &str) -> std::io::Result<()> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    f.write_all(contents.as_bytes())
}

fn hex_encode(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn hex_decode(s: &str) -> Result<[u8; 32]> {
    if s.len() != 64 || !s.is_ascii() {
        bail!("expected 64 hex characters");
    }
    let mut out = [0u8; 32];
    for (i, o) in out.iter_mut().enumerate() {
        *o = u8::from_str_radix(&s[2 * i..2 * i + 2], 16)?;
    }
    Ok(out)
}
