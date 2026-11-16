use anyhow::{Result, bail, ensure};
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use rand::{RngCore, TryRngCore};
use std::{fs::OpenOptions, io::Write, path::Path};
use zeroize::Zeroizing;

pub fn random<const N: usize>() -> [u8; N] {
    let mut bytes = [0; N];
    rand::rngs::OsRng.unwrap_err().fill_bytes(&mut bytes);
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

// Only the KEK is DPAPI-protected; the database is AEAD-sealed with this KEK.
// The explicit test key mode is never silently substituted for the OS store.
pub fn create_key(path: &Path, test_key: bool) -> Result<Zeroizing<[u8; 32]>> {
    let key = Zeroizing::new(random::<32>());
    let mut bytes = vec![if test_key { 0 } else { 1 }];
    if test_key {
        bytes.extend_from_slice(key.as_ref());
    } else {
        bytes.extend(protect(key.as_ref(), false)?);
    }
    write_new(path, &bytes)?;
    Ok(key)
}
pub fn open_key(path: &Path, allow_test_key: bool) -> Result<Zeroizing<[u8; 32]>> {
    let bytes = Zeroizing::new(std::fs::read(path)?);
    let plain = match bytes.first() {
        Some(0) if allow_test_key => Zeroizing::new(bytes[1..].to_vec()),
        Some(1) => Zeroizing::new(protect(&bytes[1..], true)?),
        _ => bail!("unsupported key store or test key mode not explicitly allowed"),
    };
    ensure!(plain.len() == 32, "invalid KEK");
    let mut key = Zeroizing::new([0; 32]);
    key.copy_from_slice(&plain);
    Ok(key)
}
#[cfg(not(windows))]
fn protect(_: &[u8], _: bool) -> Result<Vec<u8>> {
    bail!("OS keystore implemented only on Windows; test keys require explicit opt-in")
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
