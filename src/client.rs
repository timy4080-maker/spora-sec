use crate::{SUITE, model::*, vault};
use anyhow::{Context, Result, bail, ensure};
use rusqlite::{Connection, OpenFlags, TransactionBehavior, params};
use serde::Serialize;
use spora_core::{
    Content, MessagePage, MessagePut, Operation, PageEntry, StorageReceipt, Transport,
    decode_operation, digest, encode_operation, from_b64, new_id, to_b64, valid_id,
};
use std::{collections::BTreeSet, path::Path, time::Duration};
use zeroize::Zeroizing;

const HARD_LIMIT: usize = 32 * 1024 * 1024;
pub(crate) const ADMISSION_LIMIT: usize = 16 * 1024 * 1024;
pub struct Client {
    conn: Connection,
    key: Zeroizing<[u8; 32]>,
    id: String,
    test_key: bool,
}
/// A complete detached transaction. Fields are private to prevent partial commits.
pub struct Prepared {
    id: String,
    revision: i64,
    state: State,
    manifest: crate::storage::Manifest,
    limit: usize,
}
#[derive(Serialize)]
pub struct Status {
    pub suite: &'static str,
    pub external_review: &'static str,
    pub device: Device,
    pub revision: i64,
    pub test_key: bool,
    pub sessions: usize,
    pub ec_prekeys: usize,
    pub kem_prekeys: usize,
    pub pending_outbox: usize,
    pub relay_stored: usize,
    pub pending_inbox: usize,
    pub quarantined: usize,
    pub pending_consumption: usize,
    pub pending_receipts: usize,
    pub message_count: usize,
    pub processed_receipts: usize,
    pub attention_required: usize,
}
fn configure(conn: &Connection) -> Result<()> {
    conn.busy_timeout(Duration::from_secs(5))?;
    conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON; PRAGMA wal_autocheckpoint=1000; PRAGMA trusted_schema=OFF;")?;
    let mode: String = conn.pragma_query_value(None, "journal_mode", |r| r.get(0))?;
    let sync: i64 = conn.pragma_query_value(None, "synchronous", |r| r.get(0))?;
    let page_size: i64 = conn.pragma_query_value(None, "page_size", |r| r.get(0))?;
    let max_pages = 128 * 1024 * 1024 / page_size;
    conn.pragma_update(None, "max_page_count", max_pages)?;
    let limit: i64 = conn.pragma_query_value(None, "max_page_count", |r| r.get(0))?;
    ensure!(
        mode == "wal" && sync == 2 && limit == max_pages,
        "unsupported SQLite durability or capacity"
    );
    Ok(())
}
fn aad(id: &str, revision: i64) -> Vec<u8> {
    format!("{SUITE}:profile:{id}:revision:{revision}").into_bytes()
}
impl Client {
    pub fn create(dir: &Path, test_key: bool) -> Result<Self> {
        // Atomic directory creation is the initialization lock. Interrupted initialization
        // is fail-closed and cannot silently recreate a live identity/key.
        vault::create_directory(dir)?;
        let key = vault::create_key(&dir.join("key.kek"), test_key)?;
        let mut conn = Connection::open(dir.join("profile.db"))?;
        configure(&conn)?;
        let id = new_id();
        let state = State::new()?;

        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute_batch("CREATE TABLE profile(id TEXT PRIMARY KEY, suite TEXT NOT NULL, revision INTEGER NOT NULL, payload BLOB NOT NULL); PRAGMA user_version=2;")?;
        tx.execute_batch(crate::storage::SCHEMA)?;
        let manifest =
            crate::storage::write(&tx, &key, &id, 0, &Default::default(), state, HARD_LIMIT)?;
        let sealed = vault::seal(
            &key,
            &aad(&id, 0),
            &Zeroizing::new(serde_json::to_vec(&manifest)?),
        )?;
        tx.execute(
            "INSERT INTO profile VALUES(?1,?2,0,?3)",
            params![id, SUITE, sealed],
        )?;
        tx.commit()?;
        Ok(Self {
            conn,
            key,
            id,
            test_key,
        })
    }
    pub fn open(dir: &Path, allow_test_key: bool) -> Result<Self> {
        let (key, test_key) = vault::open_key(&dir.join("key.kek"), allow_test_key)?;
        let conn =
            Connection::open_with_flags(dir.join("profile.db"), OpenFlags::SQLITE_OPEN_READ_WRITE)?;
        configure(&conn)?;
        let version: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
        ensure!(
            matches!(version, 1 | 2),
            "unsupported or incomplete profile"
        );
        let (id, suite): (String, String) =
            conn.query_row("SELECT id,suite FROM profile", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })?;
        ensure!(suite == SUITE, "unsupported profile suite");
        let client = Self {
            conn,
            key,
            id,
            test_key,
        };
        client.load()?;
        Ok(client)
    }
    fn load(&self) -> Result<Prepared> {
        let tx = self.conn.unchecked_transaction()?;
        let version: i64 = tx.pragma_query_value(None, "user_version", |r| r.get(0))?;
        let (revision, bytes): (i64, Vec<u8>) = tx.query_row(
            "SELECT revision,payload FROM profile WHERE id=?1",
            [&self.id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        let plain = vault::unseal(&self.key, &aad(&self.id, revision), &bytes)?;
        let (state, manifest) = match version {
            1 => {
                let mut state: State = serde_json::from_slice(&plain)?;
                state.upgrade_legacy();
                (state, Default::default())
            }
            2 => {
                let manifest = serde_json::from_slice(&plain)?;
                (
                    crate::storage::read(&tx, &self.key, &self.id, &manifest)?,
                    manifest,
                )
            }
            _ => bail!("unsupported profile version"),
        };
        tx.commit()?;
        ensure!(state.suite == SUITE, "profile suite mismatch");
        Ok(Prepared {
            id: self.id.clone(),
            revision,
            state,
            manifest,
            limit: HARD_LIMIT,
        })
    }
    pub fn commit(&mut self, prepared: Prepared) -> Result<()> {
        ensure!(prepared.id == self.id, "plan belongs to another profile");
        let revision = prepared
            .revision
            .checked_add(1)
            .context("revision exhausted")?;
        if prepared.limit == ADMISSION_LIMIT {
            ensure!(
                fs2::available_space(self.conn.path().context("missing profile path")?)?
                    >= 32 * 1024 * 1024,
                "disk admission reserve reached"
            );
        }
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current: i64 = tx.query_row(
            "SELECT revision FROM profile WHERE id=?1",
            [&self.id],
            |r| r.get(0),
        )?;
        if current != prepared.revision {
            return Err(spora_core::Error::CasConflict.into());
        }
        if prepared.manifest.is_empty() {
            tx.execute_batch(crate::storage::SCHEMA)?;
            tx.pragma_update(None, "user_version", 2)?;
        }
        let manifest = crate::storage::write(
            &tx,
            &self.key,
            &self.id,
            revision,
            &prepared.manifest,
            prepared.state,
            prepared.limit,
        )?;
        if !prepared.manifest.is_empty()
            && manifest.iter().all(|(k, v)| {
                prepared
                    .manifest
                    .get(k)
                    .is_some_and(|old| v.same_version(old))
            })
            && manifest.len() == prepared.manifest.len()
        {
            return Ok(());
        }
        let sealed = vault::seal(
            &self.key,
            &aad(&self.id, revision),
            &Zeroizing::new(serde_json::to_vec(&manifest)?),
        )?;
        let changed = tx.execute(
            "UPDATE profile SET revision=?1,payload=?2 WHERE id=?3 AND revision=?4",
            params![revision, sealed, self.id, prepared.revision],
        )?;
        ensure!(
            changed == 1,
            "CAS_CONFLICT: discard entire plan and prepare again"
        );
        if self.test_key && std::env::var("SPORA_SEC_TEST_CRASH").as_deref() == Ok("before_commit")
        {
            std::process::exit(86);
        }
        tx.commit()?;
        if self.test_key && std::env::var("SPORA_SEC_TEST_CRASH").as_deref() == Ok("after_commit") {
            std::process::exit(87);
        }
        Ok(())
    }
    fn modify<T>(&mut self, f: impl FnMut(&mut State) -> Result<T>) -> Result<T> {
        self.mutate(HARD_LIMIT, f)
    }
    fn mutate<T>(&mut self, limit: usize, mut f: impl FnMut(&mut State) -> Result<T>) -> Result<T> {
        for _ in 0..8 {
            let mut plan = self.load()?;
            let value = f(&mut plan.state)?;
            plan.limit = limit;
            match self.commit(plan) {
                Ok(()) => return Ok(value),
                Err(e)
                    if matches!(
                        e.downcast_ref::<spora_core::Error>(),
                        Some(spora_core::Error::CasConflict)
                    ) =>
                {
                    continue;
                }
                Err(e) => return Err(e),
            }
        }
        Err(spora_core::Error::CasConflict.into())
    }
    pub fn device(&self) -> Result<Device> {
        Ok(self.load()?.state.device)
    }
    pub fn status(&self) -> Result<Status> {
        let p = self.load()?;
        let s = p.state;
        Ok(Status {
            suite: SUITE,
            external_review: "PENDING: M2 not accepted",
            device: s.device,
            revision: p.revision,
            test_key: self.test_key,
            sessions: s.crypto.sessions.0.len(),
            ec_prekeys: s.crypto.prekeys.0.len(),
            kem_prekeys: s.crypto.kyber.0.len(),
            pending_outbox: s
                .outbox
                .values()
                .filter(|j| !j.relay_stored || j.replay_pending)
                .count(),
            relay_stored: s.outbox.values().filter(|j| j.relay_stored).count(),
            pending_inbox: s.inbox.values().filter(|j| j.status == "pending").count(),
            quarantined: s
                .inbox
                .values()
                .filter(|j| j.status == "quarantined" || j.status == "rejected")
                .count(),
            pending_consumption: s.inbox.values().filter(|j| !j.consumed).count(),
            pending_receipts: s.receipt_intents.len(),
            message_count: s.messages.len(),
            processed_receipts: s.messages.values().map(|m| m.processed_by.len()).sum(),
            attention_required: s.sources.values().filter(|s| s.attention.is_some()).count()
                + s.outbox
                    .values()
                    .filter(|j| {
                        j.attention.is_some()
                            || (!j.relay_stored && j.put.expires_at_ms <= spora_core::now_ms())
                    })
                    .count()
                + s.inbox
                    .values()
                    .filter(|j| j.consume_attention.is_some())
                    .count(),
        })
    }
    pub fn messages(&self) -> Result<Vec<LocalMessage>> {
        Ok(self.load()?.state.messages.into_values().collect())
    }
    pub fn outgoing(&self) -> Result<Vec<Outgoing>> {
        Ok(self.load()?.state.outbox.into_values().collect())
    }
    pub fn add_source(&mut self, service: &str, endpoint: &str) -> Result<String> {
        self.mutate(ADMISSION_LIMIT, |s| s.add_source(service, endpoint))
    }
    pub fn queue_request(&self, queue: &str) -> Result<spora_core::QueueCreate> {
        Ok(self
            .load()?
            .state
            .sources
            .get(queue)
            .context("unknown queue")?
            .provision
            .clone())
    }
    pub fn queues(&self) -> Result<Vec<serde_json::Value>> {
        Ok(self
            .load()?
            .state
            .sources
            .values()
            .map(|s| {
                serde_json::json!({
                    "queue_id":s.source.queue_id,"service_id":s.source.service_id,
                    "endpoint":s.source.endpoint,"generation":s.source.generation,
                    "cursor":s.cursor,"attention":s.attention,"next_attempt_ms":s.next_attempt_ms
                })
            })
            .collect())
    }
    pub fn invite(&mut self, request: &str, fingerprint: &str, now: i64) -> Result<Invitation> {
        self.invite_routes(request, fingerprint, now, &[])
    }
    pub fn invite_routes(
        &mut self,
        request: &str,
        fingerprint: &str,
        now: i64,
        queues: &[String],
    ) -> Result<Invitation> {
        ensure!(valid_id(request), "invalid invitation request ID");
        self.mutate(ADMISSION_LIMIT, |s| {
            s.invite_routes(request, fingerprint, now, queues)
        })
    }
    pub fn import(
        &mut self,
        inv: Invitation,
        expected: &str,
        conversation: &str,
        now: i64,
    ) -> Result<String> {
        self.mutate(ADMISSION_LIMIT, |s| {
            s.import(inv.clone(), expected, conversation, now)
        })
    }
    pub fn prepare_send(
        &self,
        request: &str,
        peers: &[String],
        text: &str,
        now: i64,
    ) -> Result<(Prepared, String)> {
        ensure!(
            valid_id(request)
                && !text.is_empty()
                && text.len() <= 4096
                && !peers.is_empty()
                && peers.len() <= 8,
            "invalid send request"
        );
        let mut peers = peers.to_vec();
        peers.sort();
        ensure!(
            peers.windows(2).all(|w| w[0] != w[1]),
            "duplicate recipient device"
        );
        let mut plan = self.load()?;
        let signature = digest(&serde_json::to_vec(&(&peers, text))?);
        if let Some((old_sig, id)) = plan.state.requests.get(request) {
            ensure!(*old_sig == signature, "idempotency conflict");
            let id = id.clone();
            return Ok((plan, id));
        }
        plan.limit = ADMISSION_LIMIT;
        let conversation = plan
            .state
            .peers
            .get(&peers[0])
            .context("unknown recipient")?
            .conversation
            .clone();
        ensure!(
            peers.iter().all(|p| plan
                .state
                .peers
                .get(p)
                .is_some_and(|p| p.conversation == conversation)),
            "recipient conversations differ"
        );
        let op = plan
            .state
            .operation(conversation, Content::Text(text.into()), now)?;
        plan.state.enqueue(&peers, &op, now)?;
        let id = op.message_id.clone();
        plan.state.messages.insert(
            id.clone(),
            LocalMessage {
                operation: op,
                outgoing: true,
                recipients: peers,
                processed_by: BTreeSet::new(),
            },
        );
        plan.state
            .requests
            .insert(request.into(), (signature, id.clone()));
        Ok((plan, id))
    }
    pub fn send(
        &mut self,
        request: &str,
        peers: &[String],
        text: &str,
        now: i64,
    ) -> Result<String> {
        for _ in 0..8 {
            let (plan, id) = self.prepare_send(request, peers, text, now)?;
            match self.commit(plan) {
                Ok(()) => return Ok(id),
                Err(e)
                    if matches!(
                        e.downcast_ref::<spora_core::Error>(),
                        Some(spora_core::Error::CasConflict)
                    ) =>
                {
                    continue;
                }
                Err(e) => return Err(e),
            }
        }
        Err(spora_core::Error::CasConflict.into())
    }
    pub fn dispatch(&mut self, transport: &impl Transport, now: i64) -> Result<usize> {
        let jobs: Vec<_> = self
            .load()?
            .state
            .outbox
            .values()
            .filter(|j| {
                (!j.relay_stored || j.replay_pending)
                    && j.attention.is_none()
                    && j.next_attempt_ms <= now
                    && j.put.expires_at_ms > now
            })
            .cloned()
            .collect();
        let mut count = 0;
        for job in jobs {
            let mut result = transport.put(&job.route.route, &job.delivery_id, &job.put, now);
            if let Ok(receipt) = &result
                && validate_receipt(&job, receipt).is_err()
            {
                result = Err(spora_core::Error::Binding);
            }
            count += self.modify(|s| {
                let j = s
                    .outbox
                    .get_mut(&job.delivery_id)
                    .context("job disappeared")?;
                if j.relay_stored && !j.replay_pending {
                    return Ok(0);
                }
                if result.is_ok() {
                    j.relay_stored = true;
                    j.replay_pending = false;
                } else {
                    j.attempts = j.attempts.saturating_add(1);
                    j.next_attempt_ms = retry_at(now, j.attempts, result.as_ref().err());
                    j.attention = attention(j.attempts, result.as_ref().err());
                }
                Ok(usize::from(result.is_ok()))
            })?;
        }
        Ok(count)
    }
    /// TX1: validate page, save ciphertext and consumption intent, advance cursor.
    /// No decrypt and no network acknowledgement occurs inside this transaction.
    pub fn fetch(&mut self, transport: &impl Transport, now: i64) -> Result<usize> {
        self.fetch_limit(transport, now, 32)
    }
    pub fn fetch_limit(
        &mut self,
        transport: &impl Transport,
        now: i64,
        limit: usize,
    ) -> Result<usize> {
        ensure!((1..=32).contains(&limit), "fetch limit must be 1..32");
        let sources: Vec<_> = self
            .load()?
            .state
            .sources
            .values()
            .filter(|s| s.attention.is_none() && s.next_attempt_ms <= now)
            .cloned()
            .collect();
        let mut count = 0;
        for source in sources {
            let mut page = transport.fetch(&source.source, source.cursor, limit, now);
            if let Ok(p) = &page
                && (p.items.len() > limit || validate_page(&source, p, now).is_err())
            {
                page = Err(spora_core::Error::Binding);
            }
            match page {
                Ok(page) => {
                    count += self.mutate(
                        if page.items.is_empty() {
                            HARD_LIMIT
                        } else {
                            ADMISSION_LIMIT
                        },
                        |s| {
                            let mut inserted = 0;
                            let local = s
                                .sources
                                .get_mut(&source.source.queue_id)
                                .context("source disappeared")?;
                            if local.cursor != source.cursor || local.attention.is_some() {
                                return Ok(0);
                            }
                            if page.items.iter().any(|entry| {
                                let key =
                                    inbox_key(&source.source.queue_id, &entry.receipt.delivery_id);
                                s.inbox.get(&key).is_some_and(|old| {
                                    old.entry.receipt != entry.receipt
                                        || old.entry.envelope_b64url != entry.envelope_b64url
                                })
                            }) {
                                local.attention = Some("CONFLICTING_REPLAY".into());
                                return Ok(0);
                            }
                            local.cursor = page.next_after.parse()?;
                            local.failures = 0;
                            local.next_attempt_ms = 0;
                            for entry in &page.items {
                                let key =
                                    inbox_key(&source.source.queue_id, &entry.receipt.delivery_id);
                                if let std::collections::btree_map::Entry::Vacant(v) =
                                    s.inbox.entry(key)
                                {
                                    v.insert(Incoming {
                                        source: source.source.queue_id.clone(),
                                        entry: entry.clone(),
                                        status: "pending".into(),
                                        consumed: false,
                                        next_consume_ms: 0,
                                        attempts: 0,
                                        consume_attention: None,
                                    });
                                    inserted += 1;
                                }
                            }
                            Ok(inserted)
                        },
                    )?;
                }
                Err(error) => self.modify(|s| {
                    let local = s
                        .sources
                        .get_mut(&source.source.queue_id)
                        .context("source disappeared")?;
                    local.failures = local.failures.saturating_add(1);
                    local.next_attempt_ms = retry_at(now, local.failures, Some(&error));
                    local.attention = attention(local.failures, Some(&error));
                    Ok(())
                })?,
            }
        }
        Ok(count)
    }
    pub fn consume(&mut self, transport: &impl Transport, now: i64) -> Result<usize> {
        let state = self.load()?.state;
        let jobs: Vec<_> = state
            .inbox
            .iter()
            .filter(|(_, j)| {
                !j.consumed && j.consume_attention.is_none() && j.next_consume_ms <= now
            })
            .map(|(k, j)| (k.clone(), j.clone()))
            .collect();
        let mut count = 0;
        for (key, job) in jobs {
            let source = &state
                .sources
                .get(&job.source)
                .context("source missing")?
                .source;
            let result = transport.consume(source, &job.entry.receipt.delivery_id, now);
            count += self.modify(|s| {
                let j = s.inbox.get_mut(&key).context("inbox missing")?;
                if j.consumed {
                    return Ok(0);
                }
                if result.is_ok() {
                    j.consumed = true;
                } else {
                    j.attempts = j.attempts.saturating_add(1);
                    j.next_consume_ms = retry_at(now, j.attempts, result.as_ref().err());
                    j.consume_attention = attention(j.attempts, result.as_ref().err());
                }
                Ok(usize::from(result.is_ok()))
            })?;
        }
        Ok(count)
    }
    /// TX2: library mutations + application result + durable receipt intent.
    pub fn apply(&mut self, now: i64) -> Result<usize> {
        let keys: Vec<_> = self
            .load()?
            .state
            .inbox
            .iter()
            .filter(|(_, i)| i.status == "pending")
            .map(|(k, _)| k.clone())
            .collect();
        let mut applied = 0;
        for key in keys {
            applied += self.modify(|s| {
                let item = s.inbox.get(&key).context("inbox missing")?.clone();
                if item.status != "pending" {
                    return Ok(0);
                }
                let route = &s
                    .sources
                    .get(&item.source)
                    .context("source missing")?
                    .secure;
                let cipher = from_b64(&item.entry.envelope_b64url)?;
                let packet = match route.unwrap(&cipher) {
                    Ok(p) => p,
                    Err(_) => {
                        s.inbox.get_mut(&key).unwrap().status = "quarantined".into();
                        return Ok(0);
                    }
                };
                let packet_digest = digest(&packet);
                // One inner ciphertext can arrive over several independently wrapped routes.
                let cipher_key = format!("cipher:{packet_digest}");
                if let Some(logical) = s.seen.get(&cipher_key).cloned() {
                    s.repeat_receipt(&logical, now);
                    s.inbox.get_mut(&key).unwrap().status = "duplicate".into();
                    return Ok(0);
                }
                let (peer, plain) = match s.decrypt(&packet) {
                    Ok(v) => v,
                    Err(_) => {
                        s.inbox.get_mut(&key).unwrap().status = "quarantined".into();
                        return Ok(0);
                    }
                };
                // A cryptographically valid but application-invalid message still consumes
                // the ratchet/prekeys. It does not reserve an application message ID.

                s.seen
                    .insert(format!("cipher:{packet_digest}"), "decrypted".into());
                s.retention
                    .insert(cipher_key.clone(), item.entry.receipt.expires_at_ms);
                let op = match decode_operation(&plain) {
                    Ok(op) => op,
                    Err(_) => {
                        s.inbox.get_mut(&key).unwrap().status = "rejected".into();
                        return Ok(0);
                    }
                };
                let trusted = &s.peers[&peer];
                if op.sender_device != peer
                    || op.device_generation != trusted.invitation.body.device.generation
                    || op.conversation_id != trusted.conversation
                    || now > op.deliver_before_ms.saturating_add(30_000)
                {
                    s.inbox.get_mut(&key).unwrap().status = "rejected".into();
                    return Ok(0);
                }
                let logical = format!("logical:{peer}:{}", op.message_id);
                if let Some(existing) = s.seen.get(&logical) {
                    s.inbox.get_mut(&key).unwrap().status = if existing == &digest(&plain) {
                        s.repeat_receipt(&logical, now);
                        s.seen.insert(cipher_key.clone(), logical.clone());
                        "duplicate"
                    } else {
                        "rejected"
                    }
                    .into();
                    return Ok(0);
                }
                match &op.content {
                    Content::Text(text) if !text.is_empty() && text.len() <= 4096 => {
                        s.receipt_intents.insert(
                            logical.clone(),
                            ReceiptIntent {
                                peer: peer.clone(),
                                original: op.message_id.clone(),
                                conversation: op.conversation_id.clone(),
                            },
                        );
                        s.messages.insert(
                            format!("{peer}:{}", op.message_id),
                            LocalMessage {
                                operation: op.clone(),
                                outgoing: false,
                                recipients: vec![s.device.id.clone()],
                                processed_by: BTreeSet::new(),
                            },
                        );
                    }
                    Content::Receipt {
                        original_message_id,
                        read: false,
                    } => {
                        let Some(original) = s.messages.get_mut(original_message_id).filter(|m| {
                            m.outgoing
                                && m.recipients.contains(&peer)
                                && m.operation.conversation_id == op.conversation_id
                        }) else {
                            s.inbox.get_mut(&key).unwrap().status = "rejected".into();
                            return Ok(0);
                        };
                        original.processed_by.insert(peer);
                    }
                    _ => {
                        s.inbox.get_mut(&key).unwrap().status = "rejected".into();
                        return Ok(0);
                    }
                }
                s.seen.insert(cipher_key, logical.clone());
                s.retention.insert(logical.clone(), op.deliver_before_ms);
                s.seen.insert(logical, digest(&plain));
                s.inbox.get_mut(&key).unwrap().status = "applied".into();
                Ok(1)
            })?;
        }
        Ok(applied)
    }
    /// A failed receipt encryption leaves the receipt intent and ratchet unchanged.
    pub fn prepare_receipts(&mut self, now: i64) -> Result<usize> {
        let intents = self.load()?.state.receipt_intents;
        let mut count = 0;
        for (id, intent) in intents {
            count += self.modify(|s| {
                if !s.receipt_intents.contains_key(&id) {
                    return Ok(0);
                }
                let op = s.operation(
                    intent.conversation.clone(),
                    Content::Receipt {
                        original_message_id: intent.original.clone(),
                        read: false,
                    },
                    now,
                )?;
                s.enqueue(std::slice::from_ref(&intent.peer), &op, now)?;
                s.receipt_intents.remove(&id);
                s.receipt_cache.insert(id.clone(), op.message_id.clone());
                Ok(1)
            })?;
        }
        Ok(count)
    }
    pub fn gc(&mut self, now: i64, prune_expired_history: bool) -> Result<()> {
        self.modify(|s| {
            s.collect(now, prune_expired_history);
            Ok(())
        })
    }
    pub fn resume_source(&mut self, queue: &str) -> Result<()> {
        self.modify(|s| {
            let source = s.sources.get_mut(queue).context("unknown queue")?;
            source.attention = None;
            source.failures = 0;
            source.next_attempt_ms = 0;
            Ok(())
        })
    }
    pub fn retry_attention(&mut self) -> Result<()> {
        self.modify(|s| {
            for j in s.outbox.values_mut().filter(|j| j.attention.is_some()) {
                j.attention = None;
                j.attempts = 0;
                j.next_attempt_ms = 0;
            }
            for j in s.inbox.values_mut() {
                if j.consume_attention.take().is_some() {
                    j.attempts = 0;
                    j.next_consume_ms = 0;
                }
                if j.status == "quarantined" {
                    j.status = "pending".into();
                }
            }
            for source in s.sources.values_mut() {
                if source.attention.is_none()
                    || source.attention.as_deref() == Some("CONFLICTING_REPLAY")
                {
                    continue;
                }
                source.attention = None;
                source.failures = 0;
                source.next_attempt_ms = 0;
            }
            Ok(())
        })
    }
}
impl State {
    fn operation(
        &mut self,
        conversation_id: String,
        content: Content,
        now: i64,
    ) -> Result<Operation> {
        let sequence = self
            .streams
            .entry(conversation_id.clone())
            .or_insert(self.next_sequence);
        *sequence = sequence.checked_add(1).context("sequence exhausted")?;
        Ok(Operation {
            message_id: new_id(),
            conversation_id,
            sender_device: self.device.id.clone(),
            device_generation: self.device.generation.clone(),
            sender_seq: *sequence,
            deliver_before_ms: now
                .checked_add(spora_core::RETENTION_MS)
                .context("time overflow")?,
            content,
        })
    }
    fn enqueue(&mut self, peers: &[String], op: &Operation, now: i64) -> Result<()> {
        let plain = encode_operation(op)?;
        for peer in peers {
            let packet = self.encrypt(peer, &plain, now)?;
            let routes = self.peers[peer].invitation.body.routes.clone();
            for route in routes {
                let envelope = route.wrap(&packet)?;
                ensure!(
                    envelope.len() <= spora_core::MAX_ENVELOPE,
                    "envelope exceeds IP capability; entire plan discarded"
                );
                let delivery_id = new_id();
                self.outbox.insert(
                    delivery_id.clone(),
                    Outgoing {
                        delivery_id,
                        message_id: op.message_id.clone(),
                        peer: peer.clone(),
                        put: MessagePut {
                            generation: route.route.generation.clone(),
                            envelope_b64url: to_b64(&envelope),
                            envelope_sha256: digest(&envelope),
                            expires_at_ms: op.deliver_before_ms,
                        },
                        route,
                        relay_stored: false,
                        replay_pending: false,
                        next_attempt_ms: 0,
                        attempts: 0,
                        attention: None,
                    },
                );
            }
        }
        Ok(())
    }
}
fn inbox_key(queue: &str, delivery: &str) -> String {
    format!("{queue}:{delivery}")
}
fn retry_at(now: i64, attempts: u32, error: Option<&spora_core::Error>) -> i64 {
    let minimum = match error {
        Some(spora_core::Error::RetryAfter { retry_after_ms, .. }) => {
            (*retry_after_ms).min(i64::MAX as u64) as i64
        }
        _ => 0,
    };
    let cap = (1000_i64 << attempts.min(5)).min(30_000);
    let jitter = (u64::from_le_bytes(vault::random()) % (cap as u64 + 1)) as i64;
    now.saturating_add(minimum.max(jitter))
}
fn attention(attempts: u32, error: Option<&spora_core::Error>) -> Option<String> {
    error.filter(|e| !e.retryable() || attempts >= 16).map(|e| {
        if attempts >= 16 {
            "RETRY_BUDGET_EXHAUSTED".into()
        } else {
            e.code().into()
        }
    })
}
fn validate_receipt(job: &Outgoing, r: &StorageReceipt) -> Result<()> {
    let route = &job.route.route;
    ensure!(
        r.service_id == route.service_id
            && r.queue_id == route.queue_id
            && r.generation == route.generation
            && r.delivery_id == job.delivery_id
            && r.envelope_sha256 == job.put.envelope_sha256
            && r.expires_at_ms == job.put.expires_at_ms
            && r.accepted_at_ms < r.expires_at_ms
            && r.seq.parse::<u64>()? > 0,
        "Relay receipt binding mismatch"
    );
    Ok(())
}
fn validate_page(source: &LocalSource, page: &MessagePage, now: i64) -> Result<()> {
    let s = &source.source;
    ensure!(
        page.queue_id == s.queue_id && page.generation == s.generation && page.items.len() <= 32,
        "page binding mismatch"
    );
    let mut seq = source.cursor;
    let mut ids = BTreeSet::new();
    for PageEntry {
        receipt: r,
        envelope_b64url,
    } in &page.items
    {
        let bytes = from_b64(envelope_b64url)?;
        let next = r.seq.parse::<u64>()?;
        ensure!(
            r.seq == next.to_string()
                && next > seq
                && r.service_id == s.service_id
                && r.queue_id == s.queue_id
                && r.generation == s.generation
                && valid_id(&r.delivery_id)
                && ids.insert(&r.delivery_id),
            "invalid receipt order/binding"
        );
        ensure!(
            bytes.len() <= spora_core::MAX_ENVELOPE
                && !bytes.is_empty()
                && digest(&bytes) == r.envelope_sha256
                && r.accepted_at_ms <= now.saturating_add(30_000)
                && r.accepted_at_ms >= 0
                && r.expires_at_ms <= r.accepted_at_ms.saturating_add(spora_core::RETENTION_MS)
                && r.expires_at_ms > r.accepted_at_ms,
            "invalid envelope receipt"
        );
        seq = next;
    }
    let next: u64 = page.next_after.parse()?;
    ensure!(
        page.next_after == next.to_string()
            && next >= seq
            && (!page.has_more || !page.items.is_empty()),
        "invalid page cursor"
    );
    // C-03 may advance over expired/consumed records. It cannot move backwards.
    if next < source.cursor {
        bail!("cursor rollback");
    }
    Ok(())
}
#[cfg(test)]
#[path = "client_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "review_tests.rs"]
mod review_tests;
