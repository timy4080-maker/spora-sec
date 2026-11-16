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
    Ok(())
}
fn aad(id: &str, revision: i64) -> Vec<u8> {
    format!("{SUITE}:profile:{id}:revision:{revision}").into_bytes()
}
impl Client {
    pub fn create(dir: &Path, test_key: bool) -> Result<Self> {
        // Atomic directory creation is the initialization lock. Interrupted initialization
        // is fail-closed and cannot silently recreate a live identity/key.
        std::fs::create_dir(dir).context("profile already exists or parent absent")?;
        let key = vault::create_key(&dir.join("key.kek"), test_key)?;
        let mut conn = Connection::open(dir.join("profile.db"))?;
        configure(&conn)?;
        let id = new_id();
        let state = State::new()?;
        let plain = Zeroizing::new(serde_json::to_vec(&state)?);
        let sealed = vault::seal(&key, &aad(&id, 0), &plain)?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute_batch("CREATE TABLE profile(id TEXT PRIMARY KEY, suite TEXT NOT NULL, revision INTEGER NOT NULL, payload BLOB NOT NULL); PRAGMA user_version=1;")?;
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
        let key = vault::open_key(&dir.join("key.kek"), allow_test_key)?;
        let test_key = std::fs::read(dir.join("key.kek"))?.first() == Some(&0);
        let conn =
            Connection::open_with_flags(dir.join("profile.db"), OpenFlags::SQLITE_OPEN_READ_WRITE)?;
        configure(&conn)?;
        let version: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
        ensure!(version == 1, "unsupported or incomplete profile");
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
        let (revision, bytes): (i64, Vec<u8>) = self.conn.query_row(
            "SELECT revision,payload FROM profile WHERE id=?1",
            [&self.id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        let plain = vault::unseal(&self.key, &aad(&self.id, revision), &bytes)?;
        let state: State = serde_json::from_slice(&plain)?;
        ensure!(state.suite == SUITE, "profile suite mismatch");
        Ok(Prepared {
            id: self.id.clone(),
            revision,
            state,
        })
    }
    pub fn commit(&mut self, prepared: Prepared) -> Result<()> {
        ensure!(prepared.id == self.id, "plan belongs to another profile");
        let revision = prepared
            .revision
            .checked_add(1)
            .context("revision exhausted")?;
        let plain = Zeroizing::new(serde_json::to_vec(&prepared.state)?);
        ensure!(
            plain.len() <= 32 * 1024 * 1024,
            "profile budget exceeded; nothing evicted"
        );
        let sealed = vault::seal(&self.key, &aad(&self.id, revision), &plain)?;
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
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
    fn modify<T>(&mut self, f: impl FnOnce(&mut State) -> Result<T>) -> Result<T> {
        let mut plan = self.load()?;
        let value = f(&mut plan.state)?;
        self.commit(plan)?;
        Ok(value)
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
            pending_outbox: s.outbox.values().filter(|j| !j.relay_stored).count(),
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
        self.modify(|s| s.add_source(service, endpoint))
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
        ensure!(valid_id(request), "invalid invitation request ID");
        self.modify(|s| s.invite(request, fingerprint, now))
    }
    pub fn import(
        &mut self,
        inv: Invitation,
        expected: &str,
        conversation: &str,
        now: i64,
    ) -> Result<String> {
        self.modify(|s| s.import(inv, expected, conversation, now))
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
                && text.len() <= 8192
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
        let (plan, id) = self.prepare_send(request, peers, text, now)?;
        self.commit(plan)?;
        Ok(id)
    }
    pub fn dispatch(&mut self, transport: &impl Transport, now: i64) -> Result<usize> {
        let jobs: Vec<_> = self
            .load()?
            .state
            .outbox
            .values()
            .filter(|j| {
                !j.relay_stored
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
            self.modify(|s| {
                let j = s
                    .outbox
                    .get_mut(&job.delivery_id)
                    .context("job disappeared")?;
                if result.is_ok() {
                    j.relay_stored = true;
                    count += 1;
                } else {
                    j.attempts = j.attempts.saturating_add(1);
                    j.next_attempt_ms = retry_at(now, j.attempts, result.as_ref().err());
                    j.attention = attention(j.attempts, result.as_ref().err());
                }
                Ok(())
            })?;
        }
        Ok(count)
    }
    /// TX1: validate page, save ciphertext and consumption intent, advance cursor.
    /// No decrypt and no network acknowledgement occurs inside this transaction.
    pub fn fetch(&mut self, transport: &impl Transport, now: i64) -> Result<usize> {
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
            let mut page = transport.fetch(&source.source, source.cursor, 32, now);
            if let Ok(p) = &page
                && validate_page(&source, p, now).is_err()
            {
                page = Err(spora_core::Error::Binding);
            }
            match page {
                Ok(page) => {
                    self.modify(|s| {
                        let local = s
                            .sources
                            .get_mut(&source.source.queue_id)
                            .context("source disappeared")?;
                        ensure!(
                            local.cursor == source.cursor,
                            "source cursor changed; retry fetch"
                        );
                        if page.items.iter().any(|entry| {
                            let key =
                                inbox_key(&source.source.queue_id, &entry.receipt.delivery_id);
                            s.inbox.get(&key).is_some_and(|old| {
                                old.entry.receipt != entry.receipt
                                    || old.entry.envelope_b64url != entry.envelope_b64url
                            })
                        }) {
                            local.attention = Some("CONFLICTING_REPLAY".into());
                            return Ok(());
                        }
                        local.cursor = page.next_after.parse()?;
                        local.failures = 0;
                        local.next_attempt_ms = 0;
                        for entry in page.items {
                            let key =
                                inbox_key(&source.source.queue_id, &entry.receipt.delivery_id);
                            if let std::collections::btree_map::Entry::Vacant(v) =
                                s.inbox.entry(key)
                            {
                                v.insert(Incoming {
                                    source: source.source.queue_id.clone(),
                                    entry,
                                    status: "pending".into(),
                                    consumed: false,
                                    next_consume_ms: 0,
                                    attempts: 0,
                                    consume_attention: None,
                                });
                                count += 1;
                            }
                        }
                        Ok(())
                    })?;
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
            self.modify(|s| {
                let j = s.inbox.get_mut(&key).context("inbox missing")?;
                if result.is_ok() {
                    j.consumed = true;
                    count += 1;
                } else {
                    j.attempts = j.attempts.saturating_add(1);
                    j.next_consume_ms = retry_at(now, j.attempts, result.as_ref().err());
                    j.consume_attention = attention(j.attempts, result.as_ref().err());
                }
                Ok(())
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
            self.modify(|s| {
                let item = s.inbox.get(&key).context("inbox missing")?.clone();
                if item.status != "pending" {
                    return Ok(());
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
                        return Ok(());
                    }
                };
                let packet_digest = digest(&packet);
                // One inner ciphertext can arrive over several independently wrapped routes.
                if s.seen.contains_key(&format!("cipher:{packet_digest}")) {
                    s.inbox.get_mut(&key).unwrap().status = "duplicate".into();
                    return Ok(());
                }
                let mut candidate = s.clone();
                let (peer, plain) = match candidate.decrypt(&packet) {
                    Ok(v) => v,
                    Err(_) => {
                        s.inbox.get_mut(&key).unwrap().status = "quarantined".into();
                        return Ok(());
                    }
                };
                // A cryptographically valid but application-invalid message still consumes
                // the ratchet/prekeys. It does not reserve an application message ID.
                s.crypto = candidate.crypto;
                s.seen
                    .insert(format!("cipher:{packet_digest}"), "decrypted".into());
                let op = match decode_operation(&plain) {
                    Ok(op) => op,
                    Err(_) => {
                        s.inbox.get_mut(&key).unwrap().status = "rejected".into();
                        return Ok(());
                    }
                };
                let trusted = &s.peers[&peer];
                if op.sender_device != peer
                    || op.device_generation != trusted.invitation.body.device.generation
                    || op.conversation_id != trusted.conversation
                    || op.deliver_before_ms < now
                {
                    s.inbox.get_mut(&key).unwrap().status = "rejected".into();
                    return Ok(());
                }
                let logical = format!("logical:{peer}:{}", op.message_id);
                if let Some(existing) = s.seen.get(&logical) {
                    s.inbox.get_mut(&key).unwrap().status = if existing == &digest(&plain) {
                        "duplicate"
                    } else {
                        "rejected"
                    }
                    .into();
                    return Ok(());
                }
                match &op.content {
                    Content::Text(text) if !text.is_empty() && text.len() <= 8192 => {
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
                            return Ok(());
                        };
                        original.processed_by.insert(peer);
                    }
                    _ => {
                        s.inbox.get_mut(&key).unwrap().status = "rejected".into();
                        return Ok(());
                    }
                }
                s.seen.insert(logical, digest(&plain));
                s.inbox.get_mut(&key).unwrap().status = "applied".into();
                applied += 1;
                Ok(())
            })?;
        }
        Ok(applied)
    }
    /// A failed receipt encryption leaves the receipt intent and ratchet unchanged.
    pub fn prepare_receipts(&mut self, now: i64) -> Result<usize> {
        let intents = self.load()?.state.receipt_intents;
        let mut count = 0;
        for (id, intent) in intents {
            self.modify(|s| {
                if !s.receipt_intents.contains_key(&id) {
                    return Ok(());
                }
                let op = s.operation(
                    intent.conversation,
                    Content::Receipt {
                        original_message_id: intent.original,
                        read: false,
                    },
                    now,
                )?;
                s.enqueue(&[intent.peer], &op, now)?;
                s.receipt_intents.remove(&id);
                count += 1;
                Ok(())
            })?;
        }
        Ok(count)
    }
    pub fn retry_attention(&mut self) -> Result<()> {
        self.modify(|s| {
            for j in s.outbox.values_mut() {
                j.attention = None;
                j.attempts = 0;
                j.next_attempt_ms = 0;
            }
            for j in s.inbox.values_mut() {
                j.consume_attention = None;
                j.attempts = 0;
                j.next_consume_ms = 0;
                if j.status == "quarantined" {
                    j.status = "pending".into();
                }
            }
            for source in s.sources.values_mut() {
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
        self.next_sequence = self
            .next_sequence
            .checked_add(1)
            .context("sequence exhausted")?;
        Ok(Operation {
            message_id: new_id(),
            conversation_id,
            sender_device: self.device.id.clone(),
            device_generation: self.device.generation.clone(),
            sender_seq: self.next_sequence,
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
    let cap = 1000_i64.saturating_mul(1_i64 << attempts.min(8));
    let jitter = (u64::from_le_bytes(vault::random()) % (cap as u64 + 1)) as i64;
    now.saturating_add(minimum.max(1000 + jitter))
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
                && r.accepted_at_ms <= now + 60_000
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
