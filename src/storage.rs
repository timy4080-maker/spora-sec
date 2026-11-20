//! A sealed manifest binds each logical record to its random slot, version and digest.
//! The manifest and every changed/deleted record share the caller's CAS transaction.
use crate::{model::State, vault};
use anyhow::{Context, Result, ensure};
use rusqlite::{Transaction, params};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use zeroize::Zeroizing;
type Bytes = Zeroizing<Vec<u8>>;
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Slot {
    id: String,
    revision: i64,
    digest: String,
}
impl Slot {
    pub(crate) fn same_version(&self, other: &Self) -> bool {
        self.revision == other.revision && self.id == other.id
    }
}
pub(crate) type Manifest = BTreeMap<String, Slot>;
pub(crate) const SCHEMA: &str = "CREATE TABLE IF NOT EXISTS sealed_records(slot TEXT PRIMARY KEY, payload BLOB NOT NULL) WITHOUT ROWID;";
fn record_aad(profile: &str, slot: &Slot) -> Vec<u8> {
    format!("spora/record/v2/{profile}/{}/{}", slot.id, slot.revision).into_bytes()
}
fn parts(mut state: State) -> Result<BTreeMap<String, Bytes>> {
    let mut result = BTreeMap::new();
    macro_rules! split {
        ($field:ident) => {
            for (key, value) in std::mem::take(&mut state.$field) {
                result.insert(
                    format!("{}/{}", stringify!($field), key),
                    Zeroizing::new(serde_json::to_vec(&value)?),
                );
            }
        };
    }
    split!(messages);
    split!(inbox);
    split!(outbox);
    split!(requests);
    split!(seen);
    split!(peers);
    split!(sources);
    split!(invitations);
    split!(receipt_intents);
    split!(retention);
    split!(receipt_cache);
    // Core includes device identity, stream counters and provider state.
    result.insert("core".into(), Zeroizing::new(serde_json::to_vec(&state)?));
    Ok(result)
}
pub(crate) fn write(
    tx: &Transaction<'_>,
    key: &[u8; 32],
    profile: &str,
    revision: i64,
    old: &Manifest,
    state: State,
    limit: usize,
) -> Result<Manifest> {
    if limit == crate::client::ADMISSION_LIMIT {
        ensure!(
            state.inbox.len() <= 8192
                && state.outbox.len() <= 8192
                && state.seen.len() <= 32768
                && state.messages.len() <= 16384,
            "admission row limit exceeded; run gc"
        );
    }
    let parts = parts(state)?;
    if limit == crate::client::ADMISSION_LIMIT {
        for (prefix, budget) in [
            ("inbox/", 8usize << 20),
            ("outbox/", 8 << 20),
            ("seen/", 4 << 20),
            ("messages/", 8 << 20),
        ] {
            let used: usize = parts
                .range(prefix.to_string()..)
                .take_while(|(k, _)| k.starts_with(prefix))
                .map(|(k, v)| k.len() + v.len() + 160)
                .sum();
            ensure!(
                used <= budget,
                "admission byte limit exceeded for {prefix}; run gc"
            );
        }
    }
    let size: usize = parts.iter().map(|(k, v)| k.len() + v.len() + 160).sum();
    ensure!(
        size <= limit,
        "profile capacity exceeded; run gc or prune expired history"
    );
    let mut manifest = Manifest::new();
    let mut upsert=tx.prepare_cached("INSERT INTO sealed_records(slot,payload) VALUES(?1,?2) ON CONFLICT(slot) DO UPDATE SET payload=excluded.payload")?;
    for (name, data) in parts {
        let digest = spora_core::digest(&data);
        if let Some(slot) = old.get(&name).filter(|s| s.digest == digest) {
            manifest.insert(name, slot.clone());
            continue;
        }
        let slot = Slot {
            id: old
                .get(&name)
                .map(|s| s.id.clone())
                .unwrap_or_else(spora_core::new_id),
            revision,
            digest,
        };
        let encrypted = vault::seal(key, &record_aad(profile, &slot), &data)?;
        upsert.execute(params![slot.id, encrypted])?;
        manifest.insert(name, slot);
    }
    for (name, slot) in old {
        if !manifest.contains_key(name) {
            tx.execute("DELETE FROM sealed_records WHERE slot=?1", [&slot.id])?;
        }
    }
    Ok(manifest)
}
pub(crate) fn read(
    tx: &Transaction<'_>,
    key: &[u8; 32],
    profile: &str,
    manifest: &Manifest,
) -> Result<State> {
    let mut query = tx.prepare_cached("SELECT payload FROM sealed_records WHERE slot=?1")?;
    let mut read_slot = |slot: &Slot| -> Result<Bytes> {
        let cipher: Vec<u8> = query.query_row([&slot.id], |r| r.get(0))?;
        let bytes = vault::unseal(key, &record_aad(profile, slot), &cipher)?;
        ensure!(
            spora_core::digest(&bytes) == slot.digest,
            "record digest mismatch"
        );
        Ok(bytes)
    };
    let mut state: State =
        serde_json::from_slice(&read_slot(manifest.get("core").context("missing core")?)?)?;
    for (name, slot) in manifest {
        if name == "core" {
            continue;
        }
        let (field, k) = name.split_once('/').context("invalid record name")?;
        let bytes = read_slot(slot)?;
        macro_rules! restore {
            ($field:ident) => {{
                state
                    .$field
                    .insert(k.to_owned(), serde_json::from_slice(&bytes)?);
            }};
        }
        match field {
            "messages" => restore!(messages),
            "inbox" => restore!(inbox),
            "outbox" => restore!(outbox),
            "requests" => restore!(requests),
            "seen" => restore!(seen),
            "peers" => restore!(peers),
            "sources" => restore!(sources),
            "invitations" => restore!(invitations),
            "receipt_intents" => restore!(receipt_intents),
            "retention" => restore!(retention),
            "receipt_cache" => restore!(receipt_cache),
            _ => anyhow::bail!("unknown sealed record"),
        }
    }
    Ok(state)
}
