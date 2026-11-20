use crate::model::*;
use spora_core::{DEDUP_MS, RETENTION_MS};
use std::collections::BTreeSet;
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
        // Outstanding prekey messages can be sent up to 30 days after initiation and
        // remain on a relay another 7 days. An unresolved local envelope pins keys.
        let unresolved = self
            .inbox
            .values()
            .any(|j| matches!(j.status.as_str(), "pending" | "quarantined"));
        if !unresolved {
            let mut obsolete = BTreeSet::new();
            self.invitations.retain(|_, i| {
                if expired(
                    i.body
                        .expires_ms
                        .saturating_add(30 * 86_400_000 + RETENTION_MS),
                ) {
                    obsolete.insert(i.body.key_id);
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
}
