use crate::model::*;
use spora_core::{DEDUP_MS, MessagePage, RETENTION_MS};
use std::collections::{BTreeMap, BTreeSet};
#[derive(Clone, Copy, Default)]
struct Usage {
    rows: usize,
    bytes: usize,
}
impl Usage {
    fn add(&mut self, envelope_len: usize) {
        self.rows += 1;
        self.bytes += envelope_len + 1024; // encoded envelope and allowance for validated metadata
    }
    fn fits_with(self, page: Self, rows: usize, bytes: usize) -> bool {
        self.rows + page.rows <= rows && self.bytes + page.bytes <= bytes
    }
}

// Reserve before the cursor moves. Pending -> quarantined and manual retries retain this charge.
pub(crate) fn admits_unresolved(
    inbox: &BTreeMap<String, Incoming>,
    source: &LocalSource,
    page: &MessagePage,
) -> bool {
    let queue = &source.source.queue_id;
    let owner = source.grant.owner();
    let mut extra = Usage::default();
    for entry in &page.items {
        if !inbox.contains_key(&super::client::inbox_key(queue, &entry.receipt.delivery_id)) {
            extra.add(entry.envelope_b64url.len());
        }
    }
    if extra.rows == 0 {
        return true;
    }
    let (mut total, mut group, mut shared_queue) =
        (Usage::default(), Usage::default(), Usage::default());
    for job in inbox
        .values()
        .filter(|j| matches!(j.status.as_str(), "pending" | "quarantined"))
    {
        let len = job.entry.envelope_b64url.len();
        total.add(len);
        if job.quota_owner.as_deref() == owner {
            group.add(len);
            if owner.is_none() && job.source == *queue {
                shared_queue.add(len);
            }
        }
    }
    total.fits_with(extra, 1024, 4 << 20)
        && if owner.is_some() {
            group.fits_with(extra, 128, 1 << 20)
        } else {
            group.fits_with(extra, 256, 2 << 20) && shared_queue.fits_with(extra, 64, 512 << 10)
        }
}
impl State {
    pub(crate) fn upgrade_legacy(&mut self) {
        // Upgrade trusted on-disk bindings only. Legacy invitations from the wire are rejected.
        for peer in self.peers.values() {
            let device = &peer.invitation.body.device;
            let old = device.legacy_fingerprint();
            let new = device.fingerprint();
            for owner in self.crypto.owners.values_mut().filter(|o| **o == old) {
                *owner = new.clone();
            }
        }
        // Legacy cache has no authenticated operation/receipt links. Grant a full retention window.
        let expiry = spora_core::now_ms().saturating_add(RETENTION_MS);
        for key in self.seen.keys() {
            self.retention.insert(key.clone(), expiry);
        }
    }
    pub(crate) fn repeat_receipt(&mut self, logical: &str, now: i64) {
        if now < self.replay_after {
            return;
        }
        let Some(id) = self.receipt_cache.get(logical) else {
            return;
        };
        let mut reserved = false;
        for job in self.outbox.values_mut().filter(|j| {
            &j.message_id == id
                && j.put.expires_at_ms > now
                && j.relay_stored
                && !j.replay_pending
                && j.attention.is_none()
        }) {
            job.replay_pending = true;
            reserved = true;
        }
        if reserved {
            // At most one extra reservation per original, across all routes, plus a profile-wide cooldown.
            self.receipt_cache.remove(logical);
            self.replay_after = now.saturating_add(60_000);
        }
    }
    pub(crate) fn collect(&mut self, now: i64, prune_history: bool) {
        let expired = |expiry: i64| now > expiry.saturating_add(DEDUP_MS);
        self.inbox.retain(|_, j| {
            !(j.consumed
                && matches!(j.status.as_str(), "applied" | "duplicate" | "rejected")
                && expired(j.entry.receipt.expires_at_ms))
        });
        self.outbox.retain(|_, j| !expired(j.put.expires_at_ms));
        self.requests.retain(|_, (_, id)| {
            self.messages
                .get(id)
                .is_none_or(|m| !expired(m.operation.deliver_before_ms))
        });
        self.retention.retain(|k, t| {
            if expired(*t) && !self.receipt_intents.contains_key(k) {
                self.seen.remove(k);
                self.receipt_cache.remove(k);
                false
            } else {
                true
            }
        });
        if prune_history {
            self.messages.retain(|_, m| {
                !expired(m.operation.deliver_before_ms)
                    || self
                        .receipt_intents
                        .values()
                        .any(|i| i.original == m.operation.message_id)
            });
        }
        // Pending work only needs an issued set when it contains a bound prekey message.
        let deadline = |inv: &Invitation| {
            expired(
                inv.body
                    .expires_ms
                    .saturating_add(30 * 86_400_000 + RETENTION_MS),
            )
        };
        if !self.invitations.values().any(deadline) {
            return;
        }
        let pinned: BTreeSet<_> = self
            .inbox
            .values()
            .filter(|job| matches!(job.status.as_str(), "pending" | "quarantined"))
            .filter_map(|job| self.referenced_prekey(job))
            .collect();
        let mut obsolete = Vec::new();
        self.invitations.retain(|_, inv| {
            if deadline(inv) && !pinned.contains(&inv.body.key_id) {
                obsolete.push(inv.body.key_id);
                false
            } else {
                true
            }
        });
        for id in obsolete {
            self.crypto.owners.remove(&id);
            self.crypto.signed.0.remove(&id);
            self.crypto.prekeys.0.remove(&id);
            self.crypto.kyber.0.remove(&id);
        }
    }
}
