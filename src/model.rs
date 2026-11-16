use crate::{SUITE, signal::SignalState, vault};
use anyhow::{Result, ensure};
use libsignal_protocol::{DeviceId, IdentityKey, ProtocolAddress};
use serde::{Deserialize, Serialize};
use spora_core::{MessagePut, Operation, PageEntry, Route, Source, digest, new_id};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Device {
    pub id: String,
    pub generation: String,
    pub identity: Vec<u8>,
}
impl Device {
    pub fn fingerprint(&self) -> String {
        digest(
            &serde_json::to_vec(&(
                SUITE,
                "device-fingerprint",
                &self.id,
                &self.generation,
                &self.identity,
            ))
            .expect("serializable"),
        )
    }
    pub(crate) fn address(&self) -> Result<ProtocolAddress> {
        ensure!(
            spora_core::valid_id(&self.id) && spora_core::valid_id(&self.generation),
            "invalid device binding"
        );
        IdentityKey::decode(&self.identity)?;
        Ok(ProtocolAddress::new(
            format!("{}:{}", self.id, self.generation),
            DeviceId::new(1).expect("valid device number"),
        ))
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecureRoute {
    pub route: Route,
    pub wrapping_key: [u8; 32],
}
impl SecureRoute {
    pub(crate) fn aad(&self) -> Result<Vec<u8>> {
        let r = &self.route;
        Ok(serde_json::to_vec(&(
            SUITE,
            "route",
            &r.route_id,
            r.version,
            &r.destination_device,
            &r.device_generation,
            &r.service_id,
            &r.queue_id,
            &r.generation,
        ))?)
    }
    pub(crate) fn wrap(&self, packet: &[u8]) -> Result<Vec<u8>> {
        let mut bytes = b"SPSEC001".to_vec();
        bytes.extend(vault::seal(&self.wrapping_key, &self.aad()?, packet)?);
        Ok(bytes)
    }
    pub(crate) fn unwrap(&self, bytes: &[u8]) -> Result<zeroize::Zeroizing<Vec<u8>>> {
        ensure!(
            bytes.starts_with(b"SPSEC001"),
            "unsupported envelope suite; downgrade forbidden"
        );
        vault::unseal(&self.wrapping_key, &self.aad()?, &bytes[8..])
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvitationBody {
    pub suite: String,
    pub invitation_id: String,
    pub device: Device,
    pub recipient_fingerprint: String,
    pub expires_ms: i64,
    pub registration: u32,
    pub key_id: u32,
    pub prekey: Vec<u8>,
    pub signed_prekey: Vec<u8>,
    pub signed_signature: Vec<u8>,
    pub kem_prekey: Vec<u8>,
    pub kem_signature: Vec<u8>,
    pub routes: Vec<SecureRoute>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Invitation {
    pub body: InvitationBody,
    pub signature: Vec<u8>,
}
impl Invitation {
    pub(crate) fn signed_bytes(&self) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(&(SUITE, "invitation", &self.body))?)
    }
}
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Peer {
    pub invitation: Invitation,
    pub conversation: String,
}
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct LocalSource {
    pub source: Source,
    pub secure: SecureRoute,
    pub provision: spora_core::QueueCreate,
    pub cursor: u64,
    pub next_attempt_ms: i64,
    pub failures: u32,
    pub attention: Option<String>,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Outgoing {
    pub delivery_id: String,
    pub message_id: String,
    pub peer: String,
    pub route: SecureRoute,
    pub put: MessagePut,
    pub relay_stored: bool,
    pub next_attempt_ms: i64,
    pub attempts: u32,
    pub attention: Option<String>,
}
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Incoming {
    pub source: String,
    pub entry: PageEntry,
    pub status: String,
    pub consumed: bool,
    pub next_consume_ms: i64,
    pub attempts: u32,
    pub consume_attention: Option<String>,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct LocalMessage {
    pub operation: Operation,
    pub outgoing: bool,
    pub recipients: Vec<String>,
    pub processed_by: BTreeSet<String>,
}
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct ReceiptIntent {
    pub peer: String,
    pub original: String,
    pub conversation: String,
}
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct State {
    pub suite: String,
    pub device: Device,
    pub crypto: SignalState,
    pub sources: BTreeMap<String, LocalSource>,
    pub peers: BTreeMap<String, Peer>,
    pub invitations: BTreeMap<String, Invitation>,
    pub next_sequence: u64,
    pub requests: BTreeMap<String, (String, String)>,
    pub messages: BTreeMap<String, LocalMessage>,
    pub outbox: BTreeMap<String, Outgoing>,
    pub inbox: BTreeMap<String, Incoming>,
    pub seen: BTreeMap<String, String>,
    pub receipt_intents: BTreeMap<String, ReceiptIntent>,
}
impl State {
    pub(crate) fn new() -> Result<Self> {
        use libsignal_protocol::IdentityKeyPair;
        let crypto = SignalState::new();
        let device = Device {
            id: new_id(),
            generation: new_id(),
            identity: IdentityKeyPair::try_from(crypto.identity.pair.as_slice())?
                .identity_key()
                .serialize()
                .to_vec(),
        };
        Ok(Self {
            suite: SUITE.into(),
            device,
            crypto,
            sources: BTreeMap::new(),
            peers: BTreeMap::new(),
            invitations: BTreeMap::new(),
            next_sequence: 0,
            requests: BTreeMap::new(),
            messages: BTreeMap::new(),
            outbox: BTreeMap::new(),
            inbox: BTreeMap::new(),
            seen: BTreeMap::new(),
            receipt_intents: BTreeMap::new(),
        })
    }
}
pub(crate) struct Packet {
    pub from: String,
    pub to: String,
    pub kind: u8,
    pub ciphertext: Vec<u8>,
}
impl Packet {
    pub fn encode(&self) -> Result<Vec<u8>> {
        ensure!(
            spora_core::valid_id(&self.from) && spora_core::valid_id(&self.to),
            "invalid packet device ID"
        );
        let mut bytes = hex::decode(&self.from)?;
        bytes.extend(hex::decode(&self.to)?);
        bytes.push(self.kind);
        bytes.extend(&self.ciphertext);
        Ok(bytes)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() > 33 && bytes.len() <= spora_core::MAX_ENVELOPE,
            "invalid packet length"
        );
        Ok(Self {
            from: hex::encode(&bytes[..16]),
            to: hex::encode(&bytes[16..32]),
            kind: bytes[32],
            ciphertext: bytes[33..].to_vec(),
        })
    }
}
