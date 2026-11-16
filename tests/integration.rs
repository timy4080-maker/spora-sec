use anyhow::Result;
use spora_core::*;
use spora_relay::{Limits, Store};
use spora_sec::Client;
use std::{
    cell::{Cell, RefCell},
    collections::BTreeMap,
    process::Command,
};

struct Lab {
    dir: tempfile::TempDir,
    stores: BTreeMap<String, RefCell<Store>>,
    configs: Vec<spora_relay::Config>,
    lose_put: Cell<bool>,
    lose_consume: Cell<bool>,
    offline: Cell<bool>,
    now: i64,
}
impl Lab {
    fn new() -> Result<Self> {
        let dir = tempfile::tempdir()?;
        let mut stores = BTreeMap::new();
        let mut configs = vec![];
        for i in 0..2 {
            let path = dir.path().join(format!("relay{i}"));
            let config = Store::initialize(&path, Limits::default(), true)?;
            let mut store = Store::open(&path)?;
            store.ready(now_ms())?;
            stores.insert(config.service_id.clone(), RefCell::new(store));
            configs.push(config);
        }
        Ok(Self {
            dir,
            stores,
            configs,
            lose_put: Cell::new(false),
            lose_consume: Cell::new(false),
            offline: Cell::new(false),
            now: now_ms(),
        })
    }
    fn client(&self, name: &str, routes: usize) -> Result<Client> {
        let mut c = Client::create(&self.dir.path().join(name), true)?;
        for config in self.configs.iter().take(routes) {
            let queue = c.add_source(&config.service_id, "http://127.0.0.1:7780")?;
            self.stores[&config.service_id].borrow_mut().provision(
                &config.provisioning_token,
                &c.queue_request(&queue)?,
                self.now,
            )?;
        }
        Ok(c)
    }
    fn reopen(&self, name: &str) -> Result<Client> {
        Client::open(&self.dir.path().join(name), true)
    }
    fn pair(&self, a: &mut Client, b: &mut Client, conversation: &str) -> Result<()> {
        let akey = a.device()?.fingerprint();
        let bkey = b.device()?.fingerprint();
        let ai = a.invite(&new_id(), &bkey, self.now)?;
        let bi = b.invite(&new_id(), &akey, self.now)?;
        a.import(bi, &bkey, conversation, self.now)?;
        b.import(ai, &akey, conversation, self.now)?;
        Ok(())
    }
}
impl Transport for Lab {
    fn put(
        &self,
        r: &Route,
        id: &str,
        p: &MessagePut,
        now: i64,
    ) -> spora_core::Result<StorageReceipt> {
        if self.offline.get() {
            return Err(Error::Transport);
        }
        let (_, result) = self.stores[&r.service_id]
            .borrow_mut()
            .put(&r.queue_id, id, &r.write_token, p, now)
            .map_err(|_| Error::Transport)?;
        if self.lose_put.replace(false) {
            return Err(Error::Transport);
        }
        Ok(result.receipt)
    }
    fn fetch(
        &self,
        s: &Source,
        after: u64,
        limit: usize,
        now: i64,
    ) -> spora_core::Result<MessagePage> {
        if self.offline.get() {
            return Err(Error::Transport);
        }
        self.stores[&s.service_id]
            .borrow_mut()
            .fetch(&s.queue_id, &s.generation, &s.read_token, after, limit, now)
            .map_err(|_| Error::Transport)
    }
    fn consume(&self, s: &Source, id: &str, now: i64) -> spora_core::Result<()> {
        if self.offline.get() {
            return Err(Error::Transport);
        }
        self.stores[&s.service_id]
            .borrow_mut()
            .consume(&s.queue_id, &s.generation, id, &s.read_token, now)
            .map_err(|_| Error::Transport)?;
        if self.lose_consume.replace(false) {
            return Err(Error::Transport);
        }
        Ok(())
    }
}

#[test]
fn offline_two_devices_two_relays_restarts_and_end_to_end_receipts() -> Result<()> {
    let lab = Lab::new()?;
    let mut a = lab.client("alice", 2)?;
    let mut b = lab.client("bob", 2)?;
    let mut b2 = lab.client("bob2", 2)?;
    let conversation = new_id();
    lab.pair(&mut a, &mut b, &conversation)?;
    lab.pair(&mut a, &mut b2, &conversation)?;
    let peers = vec![b.device()?.id, b2.device()?.id];
    drop(b);
    drop(b2); // Both receiving devices are actually closed during initiation.
    let id = a.send(&new_id(), &peers, "artificial secret", lab.now)?;
    let jobs = a.outgoing()?;
    assert_eq!(jobs.len(), 4);
    assert_eq!(a.status()?.sessions, 2);
    assert_eq!(
        jobs.iter()
            .map(|j| &j.put.envelope_sha256)
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        4
    );
    assert_eq!(a.dispatch(&lab, lab.now)?, 4);
    assert_eq!(a.status()?.processed_receipts, 0);
    for name in ["bob", "bob2"] {
        let mut b = lab.reopen(name)?;
        assert_eq!(b.fetch(&lab, lab.now)?, 2);
        drop(b);
        let mut b = lab.reopen(name)?;
        assert_eq!(b.consume(&lab, lab.now)?, 2);
        drop(b);
        let mut b = lab.reopen(name)?;
        assert_eq!(b.status()?.message_count, 0);
        assert_eq!(b.apply(lab.now)?, 1);
        assert_eq!(b.status()?.quarantined, 0);
        assert_eq!(b.status()?.ec_prekeys, 0);
        assert_eq!(b.status()?.kem_prekeys, 0);
        drop(b);
        let mut b = lab.reopen(name)?;
        assert_eq!(b.prepare_receipts(lab.now)?, 1);
        drop(b);
        let mut b = lab.reopen(name)?;
        assert_eq!(b.dispatch(&lab, lab.now)?, 2);
    }
    drop(a);
    let mut a = lab.reopen("alice")?;
    assert_eq!(a.fetch(&lab, lab.now)?, 4);
    a.consume(&lab, lab.now)?;
    assert_eq!(a.apply(lab.now)?, 2);
    assert_eq!(
        a.messages()?
            .iter()
            .find(|m| m.operation.message_id == id)
            .unwrap()
            .processed_by
            .len(),
        2
    );
    assert_eq!(a.status()?.quarantined, 0);
    Ok(())
}

#[test]
fn lost_responses_network_outage_and_retry_keep_exact_ciphertext() -> Result<()> {
    let lab = Lab::new()?;
    let mut a = lab.client("a", 1)?;
    let mut b = lab.client("b", 1)?;
    lab.pair(&mut a, &mut b, &new_id())?;
    let request = new_id();
    let peers = vec![b.device()?.id];
    let id = a.send(&request, &peers, "retry", lab.now)?;
    let before = serde_json::to_vec(&a.outgoing()?[0].put)?;
    assert_eq!(id, a.send(&request, &peers, "retry", lab.now)?);
    assert!(a.send(&request, &peers, "different", lab.now).is_err());
    lab.lose_put.set(true);
    assert_eq!(a.dispatch(&lab, lab.now)?, 0);
    drop(a);
    let mut a = lab.reopen("a")?;
    assert_eq!(a.dispatch(&lab, lab.now + 3000)?, 1);
    assert_eq!(before, serde_json::to_vec(&a.outgoing()?[0].put)?);
    lab.offline.set(true);
    assert_eq!(b.fetch(&lab, lab.now)?, 0);
    drop(b);
    let mut b = lab.reopen("b")?;
    lab.offline.set(false);
    assert_eq!(b.fetch(&lab, lab.now + 1)?, 0);
    assert_eq!(b.fetch(&lab, lab.now + 3000)?, 1);
    lab.lose_consume.set(true);
    assert_eq!(b.consume(&lab, lab.now + 3000)?, 0);
    drop(b);
    let mut b = lab.reopen("b")?;
    assert_eq!(b.consume(&lab, lab.now + 6000)?, 1);
    assert_eq!(b.apply(lab.now + 6000)?, 1);
    assert_eq!(b.fetch(&lab, lab.now + 6000)?, 0);
    Ok(())
}

#[test]
fn stale_plan_cannot_commit_even_after_read_only_trust_change() -> Result<()> {
    let lab = Lab::new()?;
    let mut a = lab.client("a", 1)?;
    let mut b = lab.client("b", 1)?;
    lab.pair(&mut a, &mut b, &new_id())?;
    let request = new_id();
    let (old, _) = a.prepare_send(&request, &[b.device()?.id], "cas", lab.now)?;
    let mut concurrent = lab.reopen("a")?;
    concurrent.invite(&new_id(), &b.device()?.fingerprint(), lab.now)?;
    assert!(a.commit(old).is_err());
    assert_eq!(a.status()?.sessions, 0);
    assert!(a.outgoing()?.is_empty());
    a.send(&request, &[b.device()?.id], "cas", lab.now)?;
    Ok(())
}

#[test]
fn tampered_invitation_wrong_fingerprint_wrong_device_and_suite_fail_closed() -> Result<()> {
    let lab = Lab::new()?;
    let mut a = lab.client("a", 1)?;
    let mut b = lab.client("b", 1)?;
    let c = lab.client("c", 1)?;
    let inv = b.invite(&new_id(), &a.device()?.fingerprint(), lab.now)?;
    let fp = b.device()?.fingerprint();
    let conv = new_id();
    assert!(
        a.import(inv.clone(), &"0".repeat(64), &conv, lab.now)
            .is_err()
    );
    for mutation in 0..4 {
        let mut bad = inv.clone();
        match mutation {
            0 => bad.signature[0] ^= 1,
            1 => bad.body.suite = "SPORA_SYNTHETIC_ONLY_V1".into(),
            2 => bad.body.routes[0].route.destination_device = c.device()?.id,
            _ => bad.body.prekey[1] ^= 1,
        }
        assert!(a.import(bad, &fp, &conv, lab.now).is_err());
    }
    let mut c = c;
    assert!(c.import(inv.clone(), &fp, &conv, lab.now).is_err());
    a.import(inv, &fp, &conv, lab.now)?;
    assert_eq!(a.status()?.sessions, 0);
    Ok(())
}

#[test]
fn key_missing_key_swapped_corrupt_database_never_reinitialize() -> Result<()> {
    let lab = Lab::new()?;
    let a = lab.client("a", 1)?;
    let b = lab.client("b", 1)?;
    drop(a);
    drop(b);
    let path = lab.dir.path().join("a");
    let key = std::fs::read(path.join("key.kek"))?;
    std::fs::remove_file(path.join("key.kek"))?;
    assert!(lab.reopen("a").is_err());
    assert!(Client::create(&path, true).is_err());
    std::fs::copy(lab.dir.path().join("b/key.kek"), path.join("key.kek"))?;
    assert!(lab.reopen("a").is_err());
    std::fs::write(path.join("key.kek"), key)?;
    assert!(lab.reopen("a").is_ok());
    assert!(Client::open(&path, false).is_err());
    let conn = rusqlite::Connection::open(path.join("profile.db"))?;
    conn.execute("UPDATE profile SET revision=revision+1", [])?;
    assert!(lab.reopen("a").is_err());
    Ok(())
}

#[test]
fn actual_process_crash_before_and_after_atomic_commit() -> Result<()> {
    let lab = Lab::new()?;
    let mut a = lab.client("a", 1)?;
    let mut b = lab.client("b", 1)?;
    lab.pair(&mut a, &mut b, &new_id())?;
    drop(a);
    let peer = b.device()?.id;
    let request = new_id();
    let path = lab.dir.path().join("a");
    for (point, exit, pending) in [("before_commit", 86, 0), ("after_commit", 87, 1)] {
        let result = Command::new(env!("CARGO_BIN_EXE_spora-sec"))
            .args([
                "--profile",
                path.to_str().unwrap(),
                "--allow-test-key",
                "send",
                "--request",
                &request,
                "--peers",
                &peer,
                "--text",
                "process crash",
            ])
            .env("SPORA_SEC_TEST_CRASH", point)
            .output()?;
        assert_eq!(
            result.status.code(),
            Some(exit),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        let a = lab.reopen("a")?;
        assert_eq!(a.status()?.pending_outbox, pending);
        assert_eq!(a.status()?.sessions, pending);
    }
    let mut a = lab.reopen("a")?;
    let bytes = serde_json::to_vec(&a.outgoing()?[0].put)?;
    a.send(&request, &[peer], "process crash", lab.now)?;
    assert_eq!(bytes, serde_json::to_vec(&a.outgoing()?[0].put)?);
    Ok(())
}

#[test]
fn database_and_wal_do_not_contain_plaintext_or_private_key() -> Result<()> {
    let lab = Lab::new()?;
    let mut a = lab.client("a", 1)?;
    let mut b = lab.client("b", 1)?;
    lab.pair(&mut a, &mut b, &new_id())?;
    let marker = "sec01-private-message-89fe630c";
    a.send(&new_id(), &[b.device()?.id], marker, lab.now)?;
    for file in ["profile.db", "profile.db-wal"] {
        let path = lab.dir.path().join("a").join(file);
        if path.exists() {
            let bytes = std::fs::read(path)?;
            assert!(!bytes.windows(marker.len()).any(|w| w == marker.as_bytes()));
        }
    }
    Ok(())
}

#[cfg(windows)]
#[test]
fn windows_dpapi_key_round_trip_and_refusal_of_overwrite() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("dpapi");
    let c = Client::create(&path, false)?;
    let fp = c.device()?.fingerprint();
    drop(c);
    assert_eq!(Client::open(&path, false)?.device()?.fingerprint(), fp);
    assert!(Client::create(&path, false).is_err());
    Ok(())
}

#[test]
fn tampered_ciphertext_is_durable_quarantine_without_ratchet_or_receipt() -> Result<()> {
    let lab = Lab::new()?;
    let mut a = lab.client("a", 1)?;
    let mut b = lab.client("b", 1)?;
    lab.pair(&mut a, &mut b, &new_id())?;
    a.send(&new_id(), &[b.device()?.id], "tamper", lab.now)?;
    let mut j = a.outgoing()?.remove(0);
    let mut bytes = from_b64(&j.put.envelope_b64url)?;
    bytes[45] ^= 1;
    j.put.envelope_b64url = to_b64(&bytes);
    j.put.envelope_sha256 = digest(&bytes);
    lab.put(&j.route.route, &j.delivery_id, &j.put, lab.now)?;
    b.fetch(&lab, lab.now)?;
    b.consume(&lab, lab.now)?;
    b.apply(lab.now)?;
    assert_eq!(b.status()?.quarantined, 1);
    assert_eq!(b.status()?.sessions, 0);
    assert_eq!(b.status()?.ec_prekeys, 1);
    assert_eq!(b.status()?.kem_prekeys, 1);
    assert_eq!(b.status()?.pending_receipts, 0);
    drop(b);
    assert_eq!(lab.reopen("b")?.status()?.quarantined, 1);
    Ok(())
}

#[test]
fn reverse_delivery_and_duplicate_requests_preserve_messages() -> Result<()> {
    let lab = Lab::new()?;
    let mut a = lab.client("a", 1)?;
    let mut b = lab.client("b", 1)?;
    lab.pair(&mut a, &mut b, &new_id())?;
    for n in 0..5 {
        a.send(&new_id(), &[b.device()?.id], &format!("order-{n}"), lab.now)?;
    }
    let mut jobs = a.outgoing()?;
    jobs.reverse();
    for j in jobs {
        lab.put(&j.route.route, &j.delivery_id, &j.put, lab.now)?;
        lab.put(&j.route.route, &j.delivery_id, &j.put, lab.now)?;
    }
    assert_eq!(b.fetch(&lab, lab.now)?, 5);
    b.consume(&lab, lab.now)?;
    assert_eq!(b.apply(lab.now)?, 5);
    assert_eq!(b.status()?.quarantined, 0);
    assert_eq!(b.messages()?.len(), 5);
    Ok(())
}
