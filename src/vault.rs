use anyhow::{Result, bail, ensure};
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use rand::{RngCore, TryRngCore};
use std::{fs::OpenOptions, io::Write, path::Path};
use zeroize::Zeroizing;

pub fn os_rng() -> impl rand::CryptoRng {
    rand::rngs::OsRng.unwrap_err()
}
pub fn random<const N: usize>() -> [u8; N] {
    let mut bytes = [0; N];
    os_rng().fill_bytes(&mut bytes);
    bytes
}
pub fn seal(key: &[u8; 32], aad: &[u8], plain: &[u8]) -> Result<Vec<u8>> {
    let nonce = random::<24>();
    let mut result = nonce.to_vec();
    result.extend(
        XChaCha20Poly1305::new(key.into())
            .encrypt(XNonce::from_slice(&nonce), Payload { msg: plain, aad })
            .map_err(|_| anyhow::anyhow!("encryption failed"))?,
    );
    Ok(result)
}
pub fn unseal(key: &[u8; 32], aad: &[u8], blob: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    ensure!(blob.len() >= 40, "invalid sealed record");
    Ok(Zeroizing::new(
        XChaCha20Poly1305::new(key.into())
            .decrypt(
                XNonce::from_slice(&blob[..24]),
                Payload {
                    msg: &blob[24..],
                    aad,
                },
            )
            .map_err(|_| anyhow::anyhow!("authentication failed"))?,
    ))
}
pub fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    Ok(())
}

pub fn create_directory(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new().mode(0o700).create(path)?;
    }
    #[cfg(windows)]
    {
        // Apply the owner-only ACL before creating any key material.
        use std::process::Command;
        std::fs::create_dir(path)?;
        let system = std::path::PathBuf::from(
            std::env::var_os("SystemRoot").ok_or_else(|| anyhow::anyhow!("SystemRoot missing"))?,
        )
        .join("System32");
        let who = Command::new(system.join("whoami.exe"))
            .args(["/user", "/fo", "csv", "/nh"])
            .output()?;
        ensure!(who.status.success(), "could not determine user SID");
        let user = String::from_utf8_lossy(&who.stdout);
        let sid = user
            .trim()
            .rsplit(',')
            .next()
            .unwrap_or("")
            .trim_matches('"');
        ensure!(
            sid.starts_with("S-1-") && sid[2..].bytes().all(|b| b.is_ascii_digit() || b == b'-'),
            "invalid user SID"
        );
        let perms = Command::new(system.join("icacls.exe"))
            .arg(path)
            .args(["/inheritance:r", "/grant:r", &format!("*{sid}:(OI)(CI)F")])
            .output()?;
        ensure!(perms.status.success(), "could not restrict profile ACL");
    }
    Ok(())
}
// Only the KEK is DPAPI-protected; the database is AEAD-sealed with this KEK.
// The explicit test key mode is never silently substituted for the OS store.
pub fn create_key(path: &Path, test_key: bool) -> Result<Zeroizing<[u8; 32]>> {
    let key = Zeroizing::new(random::<32>());
    let mut bytes = Zeroizing::new(vec![if test_key {
        0
    } else if cfg!(target_os = "linux") {
        2
    } else {
        1
    }]);
    if test_key {
        bytes.extend_from_slice(key.as_ref());
    } else {
        bytes.extend(protect(key.as_ref(), false)?);
    }
    write_new(path, &bytes)?;
    Ok(key)
}
pub fn open_key(path: &Path, allow_test_key: bool) -> Result<(Zeroizing<[u8; 32]>, bool)> {
    let bytes = Zeroizing::new(std::fs::read(path)?);
    let plain = match bytes.first() {
        Some(0) if allow_test_key => Zeroizing::new(bytes[1..].to_vec()),
        Some(1) if cfg!(windows) => Zeroizing::new(protect(&bytes[1..], true)?),
        Some(2) if cfg!(target_os = "linux") => Zeroizing::new(protect(&bytes[1..], true)?),
        _ => bail!("unsupported key store or test key mode not explicitly allowed"),
    };
    ensure!(plain.len() == 32, "invalid KEK");
    let mut key = Zeroizing::new([0; 32]);
    key.copy_from_slice(&plain);
    Ok((key, bytes[0] == 0))
}
#[cfg(target_os = "linux")]
fn protect(bytes: &[u8], decrypt: bool) -> Result<Vec<u8>> {
    use std::{io::Read, os::unix::fs::MetadataExt};
    let dir =
        std::path::PathBuf::from(std::env::var_os("CREDENTIALS_DIRECTORY").ok_or_else(|| {
            anyhow::anyhow!("Linux OS credential spora-wrapping-key is required")
        })?);
    // The system service manager grants the service UID read access via a named
    // ACL. Its mask can appear as group-read in stat even with an empty group ACL.
    let root = Path::new("/run/credentials");
    ensure!(
        dir.parent() == Some(root) && std::fs::canonicalize(&dir)? == dir,
        "expected a systemd system service credential directory"
    );
    let root_meta = std::fs::symlink_metadata(root)?;
    let dir_meta = std::fs::symlink_metadata(&dir)?;
    ensure!(
        root_meta.is_dir()
            && root_meta.uid() == 0
            && root_meta.mode() & 0o022 == 0
            && dir_meta.is_dir()
            && dir_meta.mode() & 0o027 == 0,
        "unprotected OS credential directory"
    );
    let path = dir.join("spora-wrapping-key");
    ensure!(
        std::fs::symlink_metadata(&path)?.is_file(),
        "invalid OS credential file"
    );
    let mut file = std::fs::File::open(path)?;
    let meta = file.metadata()?;
    ensure!(
        meta.is_file() && matches!(meta.mode() & 0o777, 0o400 | 0o440) && meta.len() == 32,
        "OS credential must be a private 32-byte secret"
    );
    let mut master = Zeroizing::new([0u8; 32]);
    file.read_exact(master.as_mut())?;
    let context = b"spora/linux-credential/kek/v1";
    if decrypt {
        Ok(unseal(&master, context, bytes)?.to_vec())
    } else {
        seal(&master, context, bytes)
    }
}
#[cfg(not(any(windows, target_os = "linux")))]
fn protect(_: &[u8], _: bool) -> Result<Vec<u8>> {
    bail!("no OS keystore on this platform; test keys require explicit opt-in")
}

#[cfg(windows)]
fn protect(bytes: &[u8], decrypt: bool) -> Result<Vec<u8>> {
    use windows_sys::Win32::{Foundation::LocalFree, Security::Cryptography::*};
    let input = CRYPT_INTEGER_BLOB {
        cbData: bytes.len().try_into()?,
        pbData: bytes.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };
    // Windows owns output; always copy, clear, and free it before returning.
    unsafe {
        let ok = if decrypt {
            CryptUnprotectData(
                &input,
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        } else {
            CryptProtectData(
                &input,
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        };
        ensure!(ok != 0, "OS keystore refused operation");
        let result = std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec();
        zeroize::Zeroize::zeroize(std::slice::from_raw_parts_mut(
            output.pbData,
            output.cbData as usize,
        ));
        LocalFree(output.pbData as *mut core::ffi::c_void);
        Ok(result)
    }
}
