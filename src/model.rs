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
        let mut encoder = minicbor::Encoder::new(Vec::new());
        encoder
            .array(5)
            .unwrap()
            .str("spora/fingerprint/v2")
            .unwrap()
            .str(SUITE)
            .unwrap()
            .str(&self.id)
            .unwrap()
            .str(&self.generation)
            .unwrap()
            .bytes(&self.identity)
            .unwrap();
        digest(&encoder.into_writer())
    }
    pub(crate) fn legacy_fingerprint(&self) -> String {
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
    #[serde(default)]
    pub version: u8,
    pub body: InvitationBody,
    pub signature: Vec<u8>,
}
impl Invitation {
    pub(crate) fn signed_bytes(&self) -> Result<Vec<u8>> {
        ensure!(self.version == 2, "unsupported invitation signing version");
        let b = &self.body;
        let mut e = minicbor::Encoder::new(Vec::new());
        e.array(15)?
            .str("spora/invitation/v2")?
            .str(&b.suite)?
            .str(&b.invitation_id)?
            .array(3)?
            .str(&b.device.id)?
            .str(&b.device.generation)?
            .bytes(&b.device.identity)?
            .str(&b.recipient_fingerprint)?
            .i64(b.expires_ms)?
            .u32(b.registration)?
            .u32(b.key_id)?
            .bytes(&b.prekey)?
            .bytes(&b.signed_prekey)?
            .bytes(&b.signed_signature)?
            .bytes(&b.kem_prekey)?
            .bytes(&b.kem_signature)?
            .u8(self.version)?
            .array(b.routes.len() as u64)?;
        for secure in &b.routes {
            let r = &secure.route;
            e.array(12)?
                .str(&r.route_id)?
                .u64(r.version)?
                .str(&r.destination_device)?
                .str(&r.device_generation)?
                .str(&r.service_id)?
                .str(&r.endpoint)?
                .str(&r.queue_id)?
                .str(&r.generation)?
                .str(&r.write_token)?
                .str(&r.operator_id)?
                .str(&r.failure_domain)?
                .bytes(&secure.wrapping_key)?;
        }
        Ok(e.into_writer())
    }
}
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Peer {
    pub invitation: Invitation,
    pub conversation: String,
}
// A grant describes who received the write capability, not an authenticated message author.
// A queue whose earlier grants are unknown can never become exclusive retroactively.
#[derive(Clone, Default, Serialize, Deserialize, PartialEq, Eq, Debug)]
pub(crate) enum QueueGrant {
    Fresh,
    Exclusive(String),
    #[default]
    Shared,
}
impl QueueGrant {
    pub(crate) fn issue(&mut self, recipient: &str) {
        match self {
            Self::Fresh => *self = Self::Exclusive(recipient.to_owned()),
            Self::Exclusive(old) if old != recipient => *self = Self::Shared,
            _ => {}
        }
    }
    pub(crate) fn owner(&self) -> Option<&str> {
        match self {
            Self::Exclusive(id) => Some(id),
            _ => None,
        }
    }
}
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct LocalSource {
    #[serde(default)]
    pub grant: QueueGrant,
    #[serde(default)]
    pub quota_deferred: bool,
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
    #[serde(default)]
    pub replay_pending: bool,
    pub next_attempt_ms: i64,
    pub attempts: u32,
    pub attention: Option<String>,
}
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Incoming {
    #[serde(default)]
    pub quota_owner: Option<String>,
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
    // Legacy high watermark is the floor for streams first seen after upgrade.
    pub next_sequence: u64,
    #[serde(default)]
    pub streams: BTreeMap<String, u64>,
    #[serde(default)]
    pub retention: BTreeMap<String, i64>,
    #[serde(default)]
    pub receipt_cache: BTreeMap<String, String>,
    #[serde(default)]
    pub replay_after: i64,
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
            streams: BTreeMap::new(),
            retention: BTreeMap::new(),
            receipt_cache: BTreeMap::new(),
            replay_after: 0,
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
