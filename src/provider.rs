use crate::{SUITE, model::*, vault};
use anyhow::{Result, bail, ensure};
use libsignal_protocol::*;

use spora_core::{new_id, valid_id};
use std::time::SystemTime;

// Both decryption and retention must agree on exactly which issued set this packet names.
fn bound_prekey_id(m: &PreKeySignalMessage) -> Result<u32> {
    let id = u32::from(
        m.pre_key_id()
            .ok_or_else(|| anyhow::anyhow!("one-time EC prekey required"))?,
    );
    ensure!(
        m.kyber_pre_key_id().map(u32::from) == Some(id),
        "prekey binding mismatch"
    );
    ensure!(
        u32::from(m.signed_pre_key_id()) == id,
        "signed prekey binding mismatch"
    );
    Ok(id)
}
impl State {
    #[cfg(test)]
    pub(crate) fn invite(
        &mut self,
        request: &str,
        for_fingerprint: &str,
        now: i64,
    ) -> Result<Invitation> {
        self.invite_routes(request, for_fingerprint, now, &[])
    }
    pub(crate) fn invite_routes(
        &mut self,
        request: &str,
        for_fingerprint: &str,
        now: i64,
        queues: &[String],
    ) -> Result<Invitation> {
        ensure!(
            for_fingerprint.len() == 64 && for_fingerprint.bytes().all(|b| b.is_ascii_hexdigit()),
            "invalid recipient fingerprint"
        );
        if let Some(inv) = self.invitations.get(request) {
            ensure!(
                inv.body.recipient_fingerprint == for_fingerprint,
                "invitation request conflict"
            );
            ensure!(
                inv.version == 2,
                "legacy invitation; use a new request and verify v2 fingerprints"
            );
            ensure!(
                queues.is_empty()
                    || queues
                        .iter()
                        .eq(inv.body.routes.iter().map(|s| &s.route.queue_id)),
                "invitation request route conflict"
            );
            return Ok(inv.clone());
        }
        ensure!(
            !self.sources.is_empty(),
            "create receiving queues before invitation"
        );
        let selected = if queues.is_empty() {
            self.sources.keys().cloned().collect()
        } else {
            queues.to_vec()
        };
        ensure!(
            selected.len() <= 4
                && selected
                    .iter()
                    .collect::<std::collections::BTreeSet<_>>()
                    .len()
                    == selected.len(),
            "select up to four distinct queues"
        );
        let routes = selected
            .iter()
            .map(|q| {
                self.sources
                    .get(q)
                    .map(|s| s.secure.clone())
                    .ok_or_else(|| anyhow::anyhow!("unknown queue"))
            })
            .collect::<Result<Vec<_>>>()?;
        let c = &mut self.crypto;
        let id = c.next_key;
        c.next_key = id
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("prekey allocation exhausted"))?;
        let mut rng = crate::vault::os_rng();
        let identity = IdentityKeyPair::try_from(c.identity.pair.as_slice())?;
        let pre = KeyPair::generate(&mut rng);
        let signed = KeyPair::generate(&mut rng);
        let kem = kem::KeyPair::generate(kem::KeyType::Kyber1024, &mut rng);
        let signed_sig = identity
            .private_key()
            .calculate_signature(&signed.public_key.serialize(), &mut rng)?;
        let kem_sig = identity
            .private_key()
            .calculate_signature(&kem.public_key.serialize(), &mut rng)?;
        c.prekeys
            .0
            .insert(id, PreKeyRecord::new(id.into(), &pre).serialize()?.into());
        c.signed.0.insert(
            id,
            SignedPreKeyRecord::new(
                id.into(),
                Timestamp::from_epoch_millis(now.try_into()?),
                &signed,
                &signed_sig,
            )
            .serialize()?
            .into(),
        );
        c.kyber.0.insert(
            id,
            KyberPreKeyRecord::new(
                id.into(),
                Timestamp::from_epoch_millis(now.try_into()?),
                &kem,
                &kem_sig,
            )
            .serialize()?
            .into(),
        );
        c.owners.insert(id, for_fingerprint.into());
        let mut inv = Invitation {
            version: 2,
            body: InvitationBody {
                suite: SUITE.into(),
                invitation_id: new_id(),
                device: self.device.clone(),
                recipient_fingerprint: for_fingerprint.into(),
                expires_ms: now + spora_core::RETENTION_MS,
                registration: c.identity.registration,
                key_id: id,
                prekey: pre.public_key.serialize().to_vec(),
                signed_prekey: signed.public_key.serialize().to_vec(),
                signed_signature: signed_sig.to_vec(),
                kem_prekey: kem.public_key.serialize().to_vec(),
                kem_signature: kem_sig.to_vec(),
                routes,
            },
            signature: vec![],
        };
        inv.signature = identity
            .private_key()
            .calculate_signature(&inv.signed_bytes()?, &mut rng)?
            .to_vec();
        for queue in selected {
            self.sources
                .get_mut(&queue)
                .expect("validated source")
                .grant
                .issue(for_fingerprint);
        }
        self.invitations.insert(request.into(), inv.clone());
        Ok(inv)
    }
    pub(crate) fn import(
        &mut self,
        invitation: Invitation,
        expected: &str,
        conversation: &str,
        now: i64,
    ) -> Result<String> {
        ensure!(
            invitation.version == 2,
            "unsupported invitation version; verify v2 fingerprints"
        );
        let b = &invitation.body;
        ensure!(b.suite == SUITE, "unsupported invitation suite");
        ensure!(
            valid_id(conversation) && valid_id(&b.invitation_id),
            "invalid IDs"
        );
        ensure!(
            b.device.fingerprint() == expected
                && b.recipient_fingerprint == self.device.fingerprint(),
            "fingerprint/device binding mismatch"
        );
        ensure!(
            b.device.id != self.device.id
                && b.expires_ms > now
                && b.expires_ms <= now + spora_core::RETENTION_MS,
            "invalid invitation lifetime/device"
        );
        let identity = IdentityKey::decode(&b.device.identity)?;
        ensure!(
            identity
                .public_key()
                .verify_signature(&invitation.signed_bytes()?, &invitation.signature),
            "invalid invitation signature"
        );
        ensure!(
            identity
                .public_key()
                .verify_signature(&b.signed_prekey, &b.signed_signature)
                && identity
                    .public_key()
                    .verify_signature(&b.kem_prekey, &b.kem_signature),
            "invalid prekey signature"
        );
        ensure!(
            !b.routes.is_empty() && b.routes.len() <= 4,
            "invalid route count"
        );
        let mut queues = std::collections::BTreeSet::new();
        for r in &b.routes {
            let r = &r.route;
            ensure!(
                r.destination_device == b.device.id
                    && r.device_generation == b.device.generation
                    && r.version == 1,
                "recipient route mismatch"
            );
            ensure!(
                [&r.route_id, &r.queue_id, &r.generation, &r.service_id]
                    .iter()
                    .all(|s| valid_id(s))
                    && spora_core::from_b64(&r.write_token)?.len() == 32,
                "invalid route capability"
            );
            crate::transport::validate_endpoint(&r.endpoint, true)?;
            ensure!(
                queues.insert((&r.service_id, &r.queue_id, &r.generation)),
                "duplicate route"
            );
        }
        // Validate public-key encodings before durable acceptance.
        bundle(b)?;
        if let Some(existing) = self.peers.get(&b.device.id) {
            ensure!(
                existing.invitation.body.device.fingerprint() == expected
                    && existing.conversation == conversation,
                "identity/conversation replacement forbidden"
            );
            ensure!(
                existing.invitation.body.invitation_id == b.invitation_id,
                "refresh requires a separate reviewed protocol"
            );
            return Ok(b.device.id.clone());
        }
        let id = b.device.id.clone();
        self.crypto
            .identity
            .trusted
            .insert(b.device.address()?.to_string(), b.device.identity.clone());
        self.peers.insert(
            id.clone(),
            Peer {
                invitation,
                conversation: conversation.into(),
            },
        );
        Ok(id)
    }
    pub(crate) fn encrypt(&mut self, peer: &str, plain: &[u8], now: i64) -> Result<Vec<u8>> {
        let b = &self
            .peers
            .get(peer)
            .ok_or_else(|| anyhow::anyhow!("unknown peer"))?
            .invitation
            .body;
        let remote = b.device.address()?;
        let local = self.device.address()?;
        let c = &mut self.crypto;
        let mut rng = crate::vault::os_rng();
        futures::executor::block_on(async {
            if !c.sessions.0.contains_key(&remote.to_string()) {
                ensure!(
                    b.expires_ms > now,
                    "invitation expired before session initiation"
                );
                initiate_session(
                    &remote,
                    &local,
                    &mut c.sessions,
                    &mut c.identity,
                    &bundle(b)?,
                    SystemTime::UNIX_EPOCH + std::time::Duration::from_millis(now.try_into()?),
                    &mut rng,
                )
                .await?;
            }
            let message = message_encrypt(
                plain,
                &remote,
                &local,
                &mut c.sessions,
                &mut c.identity,
                SystemTime::UNIX_EPOCH + std::time::Duration::from_millis(now.try_into()?),
                &mut rng,
            )
            .await?;
            Packet {
                from: self.device.id.clone(),
                to: peer.into(),
                kind: message.message_type() as u8,
                ciphertext: message.serialize().to_vec(),
            }
            .encode()
        })
    }
    fn issued_prekey(&self, message: &PreKeySignalMessage, peer: &InvitationBody) -> Result<u32> {
        ensure!(
            message.registration_id() == peer.registration,
            "sender registration binding mismatch"
        );
        let id = bound_prekey_id(message)?;
        ensure!(
            self.crypto.owners.get(&id) == Some(&peer.device.fingerprint()),
            "prekey issued for another identity"
        );
        Ok(id)
    }
    pub(crate) fn referenced_prekey(&self, item: &Incoming) -> Option<u32> {
        let route = &self.sources.get(&item.source)?.secure;
        let envelope = spora_core::from_b64(&item.entry.envelope_b64url).ok()?;
        let packet = Packet::decode(&route.unwrap(&envelope).ok()?).ok()?;
        if packet.to != self.device.id || packet.kind != 3 {
            return None;
        }
        let message = PreKeySignalMessage::try_from(packet.ciphertext.as_slice()).ok()?;
        // An unknown sender may still be paired later. Preserve only the named set in that case.
        // A pinned set is a possible decoding dependency, never evidence of delivery or authorship.
        match self.peers.get(&packet.from) {
            Some(peer) => self.issued_prekey(&message, &peer.invitation.body).ok(),
            None => bound_prekey_id(&message).ok(),
        }
    }
    pub(crate) fn decrypt(&mut self, packet: &[u8]) -> Result<(String, Vec<u8>)> {
        let packet = Packet::decode(packet)?;
        ensure!(packet.to == self.device.id, "wrong recipient");
        let b = &self
            .peers
            .get(&packet.from)
            .ok_or_else(|| anyhow::anyhow!("untrusted sender"))?
            .invitation
            .body;
        let message = match packet.kind {
            2 => CiphertextMessage::SignalMessage(SignalMessage::try_from(
                packet.ciphertext.as_slice(),
            )?),
            3 => {
                let m = PreKeySignalMessage::try_from(packet.ciphertext.as_slice())?;
                self.issued_prekey(&m, b)?;
                CiphertextMessage::PreKeySignalMessage(m)
            }
            _ => bail!("unsupported Signal message type"),
        };
        let mut c = self.crypto.clone();
        let mut rng = crate::vault::os_rng();
        let plain = futures::executor::block_on(message_decrypt(
            &message,
            &b.device.address()?,
            &self.device.address()?,
            &mut c.sessions,
            &mut c.identity,
            &mut c.prekeys,
            &c.signed,
            &mut c.kyber,
            &mut rng,
        ))?;
        self.crypto = c;
        Ok((packet.from, plain))
    }
    pub(crate) fn add_source(&mut self, service: &str, endpoint: &str) -> Result<String> {
        ensure!(valid_id(service), "invalid service ID");
        crate::transport::validate_endpoint(endpoint, true)?;
        let queue = new_id();
        let generation = new_id();
        let read = spora_core::to_b64(&vault::random::<32>());
        let write = spora_core::to_b64(&vault::random::<32>());
        let admin = vault::random::<32>();
        let route = spora_core::Route {
            route_id: new_id(),
            version: 1,
            destination_device: self.device.id.clone(),
            device_generation: self.device.generation.clone(),
            service_id: service.into(),
            endpoint: endpoint.into(),
            queue_id: queue.clone(),
            generation: generation.clone(),
            write_token: write.clone(),
            operator_id: service.into(),
            failure_domain: service.into(),
        };
        let source = spora_core::Source {
            service_id: service.into(),
            endpoint: endpoint.into(),
            queue_id: queue.clone(),
            generation: generation.clone(),
            read_token: read.clone(),
        };
        self.sources.insert(
            queue.clone(),
            LocalSource {
                grant: QueueGrant::Fresh,
                quota_deferred: false,
                source,
                secure: SecureRoute {
                    route,
                    wrapping_key: vault::random(),
                },
                provision: spora_core::QueueCreate {
                    queue_id: queue.clone(),
                    generation,
                    read_token_hash: spora_core::digest(&spora_core::from_b64(&read)?),
                    write_token_hash: spora_core::digest(&spora_core::from_b64(&write)?),
                    admin_token_hash: spora_core::digest(&admin),
                },
                cursor: 0,
                next_attempt_ms: 0,
                failures: 0,
                attention: None,
            },
        );
        Ok(queue)
    }
}
fn bundle(b: &InvitationBody) -> Result<PreKeyBundle> {
    Ok(PreKeyBundle::new(
        b.registration,
        DeviceId::new(1).expect("device"),
        Some((b.key_id.into(), PublicKey::deserialize(&b.prekey)?)),
        b.key_id.into(),
        PublicKey::deserialize(&b.signed_prekey)?,
        b.signed_signature.clone(),
        b.key_id.into(),
        kem::PublicKey::deserialize(&b.kem_prekey)?,
        b.kem_signature.clone(),
        IdentityKey::decode(&b.device.identity)?,
    )?)
}
