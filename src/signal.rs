//! All libsignal callbacks operate on a detached, serializable snapshot.
//! No callback performs I/O or silently changes a trusted identity.
use async_trait::async_trait;
use libsignal_protocol::*;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

type R<T> = std::result::Result<T, SignalProtocolError>;
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct IdentityStore {
    pub pair: Vec<u8>,
    pub registration: u32,
    pub trusted: BTreeMap<String, Vec<u8>>,
}
#[async_trait(?Send)]
impl IdentityKeyStore for IdentityStore {
    async fn get_identity_key_pair(&self) -> R<IdentityKeyPair> {
        IdentityKeyPair::try_from(self.pair.as_slice())
    }
    async fn get_local_registration_id(&self) -> R<u32> {
        Ok(self.registration)
    }
    async fn get_identity(&self, a: &ProtocolAddress) -> R<Option<IdentityKey>> {
        self.trusted
            .get(&a.to_string())
            .map(|b| IdentityKey::decode(b))
            .transpose()
    }
    async fn is_trusted_identity(
        &self,
        a: &ProtocolAddress,
        key: &IdentityKey,
        _: Direction,
    ) -> R<bool> {
        Ok(self
            .trusted
            .get(&a.to_string())
            .is_some_and(|b| b.as_slice() == key.serialize().as_ref()))
    }
    async fn save_identity(&mut self, a: &ProtocolAddress, key: &IdentityKey) -> R<IdentityChange> {
        if !self
            .is_trusted_identity(a, key, Direction::Receiving)
            .await?
        {
            return Err(SignalProtocolError::UntrustedIdentity(a.clone()));
        }
        Ok(IdentityChange::NewOrUnchanged)
    }
    async fn record_received_identity(&mut self, a: &ProtocolAddress, key: &IdentityKey) -> R<()> {
        self.save_identity(a, key).await.map(|_| ())
    }
}
#[derive(Clone, Default, Serialize, Deserialize)]
pub(crate) struct Sessions(pub BTreeMap<String, Vec<u8>>);
#[async_trait(?Send)]
impl SessionStore for Sessions {
    async fn load_session(&self, a: &ProtocolAddress) -> R<Option<SessionRecord>> {
        self.0
            .get(&a.to_string())
            .map(|b| SessionRecord::deserialize(b))
            .transpose()
    }
    async fn store_session(&mut self, a: &ProtocolAddress, r: &SessionRecord) -> R<()> {
        self.0.insert(a.to_string(), r.serialize()?);
        Ok(())
    }
}
#[derive(Clone, Default, Serialize, Deserialize)]
pub(crate) struct PreKeys(pub BTreeMap<u32, Vec<u8>>);
#[async_trait(?Send)]
impl PreKeyStore for PreKeys {
    async fn get_pre_key(&self, id: PreKeyId) -> R<PreKeyRecord> {
        PreKeyRecord::deserialize(
            self.0
                .get(&u32::from(id))
                .ok_or(SignalProtocolError::InvalidPreKeyId)?,
        )
    }
    async fn save_pre_key(&mut self, id: PreKeyId, r: &PreKeyRecord) -> R<()> {
        self.0.insert(id.into(), r.serialize()?);
        Ok(())
    }
    async fn remove_pre_key(&mut self, id: PreKeyId) -> R<()> {
        self.0.remove(&id.into());
        Ok(())
    }
}
#[derive(Clone, Default, Serialize, Deserialize)]
pub(crate) struct SignedKeys(pub BTreeMap<u32, Vec<u8>>);
#[async_trait(?Send)]
impl SignedPreKeyStore for SignedKeys {
    async fn get_signed_pre_key(&self, id: SignedPreKeyId) -> R<SignedPreKeyRecord> {
        SignedPreKeyRecord::deserialize(
            self.0
                .get(&u32::from(id))
                .ok_or(SignalProtocolError::InvalidSignedPreKeyId)?,
        )
    }
    async fn save_signed_pre_key(&mut self, id: SignedPreKeyId, r: &SignedPreKeyRecord) -> R<()> {
        self.0.insert(id.into(), r.serialize()?);
        Ok(())
    }
}
#[derive(Clone, Default, Serialize, Deserialize)]
pub(crate) struct KyberKeys(pub BTreeMap<u32, Vec<u8>>);
#[async_trait(?Send)]
impl KyberPreKeyStore for KyberKeys {
    async fn get_kyber_pre_key(&self, id: KyberPreKeyId) -> R<KyberPreKeyRecord> {
        KyberPreKeyRecord::deserialize(
            self.0
                .get(&u32::from(id))
                .ok_or(SignalProtocolError::InvalidKyberPreKeyId)?,
        )
    }
    async fn save_kyber_pre_key(&mut self, id: KyberPreKeyId, r: &KyberPreKeyRecord) -> R<()> {
        self.0.insert(id.into(), r.serialize()?);
        Ok(())
    }
    async fn mark_kyber_pre_key_used(
        &mut self,
        id: KyberPreKeyId,
        _: SignedPreKeyId,
        _: &PublicKey,
    ) -> R<()> {
        // Every invitation allocates a distinct ONE-TIME KEM key. No last-resort reuse.
        self.0
            .remove(&id.into())
            .ok_or(SignalProtocolError::InvalidKyberPreKeyId)?;
        Ok(())
    }
}
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct SignalState {
    pub identity: IdentityStore,
    pub sessions: Sessions,
    pub prekeys: PreKeys,
    pub signed: SignedKeys,
    pub kyber: KyberKeys,
    pub next_key: u32,
    pub owners: BTreeMap<u32, String>,
}
impl SignalState {
    pub fn new() -> Self {
        use rand::{Rng, TryRngCore};
        let mut rng = rand::rngs::OsRng.unwrap_err();
        Self {
            identity: IdentityStore {
                pair: IdentityKeyPair::generate(&mut rng).serialize().to_vec(),
                registration: rng.random_range(1..16380),
                trusted: BTreeMap::new(),
            },
            sessions: Sessions::default(),
            prekeys: PreKeys::default(),
            signed: SignedKeys::default(),
            kyber: KyberKeys::default(),
            next_key: 1,
            owners: BTreeMap::new(),
        }
    }
}
