//! Windows only: the signed Wintun driver DLL (WireGuard LLC, see vendor/wintun/LICENSE.txt)
//! is compiled into the exe and written out on demand, so beambridge is a single file.
//!
//! The DLL is loaded by an elevated process, so it must not be swappable between being
//! written and being loaded. We keep a read-only handle open that denies other processes
//! write/delete access, and compare the file's content with the embedded bytes through
//! that handle before handing the path to the loader.

use anyhow::{Context, Result, bail};
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::os::windows::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

#[cfg(target_arch = "x86_64")]
static DLL: &[u8] = include_bytes!("../vendor/wintun/amd64/wintun.dll");
#[cfg(target_arch = "aarch64")]
static DLL: &[u8] = include_bytes!("../vendor/wintun/arm64/wintun.dll");
#[cfg(target_arch = "x86")]
static DLL: &[u8] = include_bytes!("../vendor/wintun/x86/wintun.dll");

const VERSION: &str = "0.14.1";
const FILE_SHARE_READ: u32 = 1;

/// Keeps the extracted DLL locked against modification for as long as it is alive.
pub struct Extracted {
    pub path: String,
    _guard: File,
}

pub fn extract() -> Result<Extracted> {
    let dir = dirs::data_local_dir()
        .context("no local data directory")?
        .join("beambridge");
    extract_to(&dir)
}

fn extract_to(dir: &Path) -> Result<Extracted> {
    std::fs::create_dir_all(dir)?;
    let name = format!("wintun-{VERSION}-{}.dll", std::env::consts::ARCH);
    let path = dir.join(&name);

    // Already there (for example from an earlier run, or one still running)? Reuse if identical.
    if let Ok(guard) = open_locked(&path)
        && matches_embedded(&guard)?
    {
        return finish(path, guard);
    }

    // Write under a unique name, then move into place.
    let tmp = dir.join(format!("{name}.{}.tmp", std::process::id()));
    std::fs::write(&tmp, DLL).with_context(|| format!("writing {}", tmp.display()))?;
    if let Err(e) = std::fs::rename(&tmp, &path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e).with_context(|| {
            format!("replacing {} (a different, running copy is using it?)", path.display())
        });
    }

    let guard = open_locked(&path).with_context(|| format!("opening {}", path.display()))?;
    if !matches_embedded(&guard)? {
        bail!("{} does not match the embedded driver DLL; refusing to load it", path.display());
    }
    finish(path, guard)
}

fn finish(path: PathBuf, guard: File) -> Result<Extracted> {
    Ok(Extracted { path: path.to_string_lossy().into_owned(), _guard: guard })
}

/// Open read-only and allow others only to read: nobody can write to or delete the file while we hold it.
fn open_locked(path: &Path) -> std::io::Result<File> {
    OpenOptions::new().read(true).share_mode(FILE_SHARE_READ).open(path)
}

fn matches_embedded(file: &File) -> Result<bool> {
    let mut f = file;
    let mut buf = Vec::with_capacity(DLL.len());
    f.read_to_end(&mut buf)?;
    Ok(buf == DLL)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_locks_and_reuses() {
        let dir = std::env::temp_dir().join(format!("bb-wintun-test-{}", std::process::id()));
        let first = extract_to(&dir).unwrap();
        assert_eq!(std::fs::read(&first.path).unwrap(), DLL);

        // While held, others cannot modify or delete it...
        assert!(std::fs::write(&first.path, b"evil").is_err());
        assert!(std::fs::remove_file(&first.path).is_err());
        // ...but a second extraction (another instance) reuses the identical file.
        let second = extract_to(&dir).unwrap();
        assert_eq!(first.path, second.path);

        drop((first, second));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn replaces_a_corrupted_copy() {
        let dir = std::env::temp_dir().join(format!("bb-wintun-test2-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let name = format!("wintun-{VERSION}-{}.dll", std::env::consts::ARCH);
        std::fs::write(dir.join(&name), b"tampered").unwrap();
        let e = extract_to(&dir).unwrap();
        assert_eq!(std::fs::read(&e.path).unwrap(), DLL);
        drop(e);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
