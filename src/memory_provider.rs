use std::{
    collections::{BTreeMap, HashMap},
    marker::PhantomData,
    sync::RwLock,
};

use openmls_rust_crypto::RustCrypto;
use openmls_traits::{
    public_storage::PublicStorageProvider,
    storage::{
        traits::{self, GroupId},
        Entity, CURRENT_VERSION,
    },
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::{
    group::errors::StorageError,
    provider_traits::{MlsAssistProvider, MlsAssistStorageProvider},
};

#[derive(Serialize, Deserialize, Default)]
struct PublicGroupState {
    treesync: Vec<u8>,
    interim_transcript_hash: Vec<u8>,
    context: Vec<u8>,
    confirmation_tag: Vec<u8>,
    proposal_queue: BTreeMap<Vec<u8>, Vec<u8>>,
}

impl PublicGroupState {
    fn is_empty(&self) -> bool {
        self.treesync.is_empty()
            && self.interim_transcript_hash.is_empty()
            && self.context.is_empty()
            && self.confirmation_tag.is_empty()
            && self.proposal_queue.is_empty()
    }
}

enum DataType {
    TreeSync,
    InterimTranscriptHash,
    Context,
    ConfirmationTag,
}

pub trait Codec {
    type Error: std::error::Error + std::fmt::Debug;

    fn to_vec<T: Serialize>(payload: &T) -> Result<Vec<u8>, Self::Error>;

    fn from_slice<T: DeserializeOwned>(data: &[u8]) -> Result<T, Self::Error>;
}

#[derive(Serialize, Deserialize, Default)]
pub struct MlsAssistMemoryStorage<C: Codec> {
    past_group_states: RwLock<HashMap<Vec<u8>, Vec<u8>>>,
    group_infos: RwLock<HashMap<Vec<u8>, Vec<u8>>>,
    group_states: RwLock<HashMap<Vec<u8>, PublicGroupState>>,
    _codec: PhantomData<C>,
}

impl<C: Codec> MlsAssistMemoryStorage<C> {
    fn write_payload<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        Payload: Entity<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        payload: &Payload,
        data_type: DataType,
    ) -> Result<(), C::Error> {
        let group_id_bytes = C::to_vec(group_id)?;
        let payload_bytes = C::to_vec(payload)?;
        let mut group_states = self.group_states.write().unwrap();
        let public_group_state = group_states.entry(group_id_bytes).or_default();
        match data_type {
            DataType::TreeSync => {
                public_group_state.treesync = payload_bytes;
            }
            DataType::InterimTranscriptHash => {
                public_group_state.interim_transcript_hash = payload_bytes;
            }
            DataType::Context => {
                public_group_state.context = payload_bytes;
            }
            DataType::ConfirmationTag => {
                public_group_state.confirmation_tag = payload_bytes;
            }
        };
        Ok(())
    }

    fn read_payload<GroupId: traits::GroupId<CURRENT_VERSION>, Payload: Entity<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
        data_type: DataType,
    ) -> Result<Option<Payload>, C::Error> {
        let group_id_bytes = C::to_vec(group_id)?;
        let group_states = self.group_states.read().unwrap();
        if let Some(public_group_state) = group_states.get(&group_id_bytes) {
            let payload_bytes = match data_type {
                DataType::TreeSync => &public_group_state.treesync,
                DataType::InterimTranscriptHash => &public_group_state.interim_transcript_hash,
                DataType::Context => &public_group_state.context,
                DataType::ConfirmationTag => &public_group_state.confirmation_tag,
            };
            if payload_bytes.is_empty() {
                return Ok(None);
            }
            C::from_slice(payload_bytes).map(Some)
        } else {
            Ok(None)
        }
    }

    fn delete_payload<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
        data_type: DataType,
    ) -> Result<(), C::Error> {
        let group_id_bytes = C::to_vec(group_id)?;
        let mut group_states = self.group_states.write().unwrap();
        if let Some(public_group_state) = group_states.get_mut(&group_id_bytes) {
            match data_type {
                DataType::TreeSync => {
                    public_group_state.treesync.clear();
                }
                DataType::InterimTranscriptHash => {
                    public_group_state.interim_transcript_hash.clear();
                }
                DataType::Context => {
                    public_group_state.context.clear();
                }
                DataType::ConfirmationTag => {
                    public_group_state.confirmation_tag.clear();
                }
            };
            if public_group_state.is_empty() {
                group_states.remove(&group_id_bytes);
            }
        }
        Ok(())
    }
}

impl<C: Codec> PublicStorageProvider<CURRENT_VERSION> for MlsAssistMemoryStorage<C> {
    /// An opaque error returned by all methods on this trait.
    type PublicError = C::Error;

    /// Write the TreeSync tree.
    fn write_tree<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        TreeSync: traits::TreeSync<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        tree: &TreeSync,
    ) -> Result<(), Self::PublicError> {
        self.write_payload(group_id, tree, DataType::TreeSync)
    }

    /// Write the interim transcript hash.
    fn write_interim_transcript_hash<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        InterimTranscriptHash: traits::InterimTranscriptHash<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        interim_transcript_hash: &InterimTranscriptHash,
    ) -> Result<(), Self::PublicError> {
        self.write_payload(
            group_id,
            interim_transcript_hash,
            DataType::InterimTranscriptHash,
        )
    }

    /// Write the group context.
    fn write_context<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        GroupContext: traits::GroupContext<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        group_context: &GroupContext,
    ) -> Result<(), Self::PublicError> {
        self.write_payload(group_id, group_context, DataType::Context)
    }

    /// Write the confirmation tag.
    fn write_confirmation_tag<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ConfirmationTag: traits::ConfirmationTag<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        confirmation_tag: &ConfirmationTag,
    ) -> Result<(), Self::PublicError> {
        self.write_payload(group_id, confirmation_tag, DataType::ConfirmationTag)
    }

    /// Enqueue a proposal.
    fn queue_proposal<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
        QueuedProposal: traits::QueuedProposal<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        proposal_ref: &ProposalRef,
        proposal: &QueuedProposal,
    ) -> Result<(), Self::PublicError> {
        let group_id_bytes = C::to_vec(group_id)?;
        let proposal_ref_bytes = C::to_vec(proposal_ref)?;
        let proposal_bytes = C::to_vec(proposal)?;
        let mut group_states = self.group_states.write().unwrap();
        let public_group_state = group_states.entry(group_id_bytes).or_default();
        public_group_state
            .proposal_queue
            .insert(proposal_ref_bytes, proposal_bytes);
        Ok(())
    }

    /// Returns all queued proposals for the group with group id `group_id`, or an empty vector of none are stored.
    fn queued_proposals<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
        QueuedProposal: traits::QueuedProposal<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<(ProposalRef, QueuedProposal)>, Self::PublicError> {
        let group_id_bytes = C::to_vec(group_id)?;
        let group_states = self.group_states.read().unwrap();
        let mut proposals = Vec::new();
        if let Some(public_group_state) = group_states.get(&group_id_bytes) {
            for (proposal_ref_bytes, proposal_bytes) in &public_group_state.proposal_queue {
                let proposal_ref = C::from_slice(proposal_ref_bytes)?;
                let proposal = C::from_slice(proposal_bytes)?;
                proposals.push((proposal_ref, proposal));
            }
        }
        Ok(proposals)
    }

    /// Returns the TreeSync tree for the group with group id `group_id`.
    fn tree<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        TreeSync: traits::TreeSync<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<TreeSync>, Self::PublicError> {
        self.read_payload(group_id, DataType::TreeSync)
    }

    /// Returns the group context for the group with group id `group_id`.
    fn group_context<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        GroupContext: traits::GroupContext<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<GroupContext>, Self::PublicError> {
        self.read_payload(group_id, DataType::Context)
    }

    /// Returns the interim transcript hash for the group with group id `group_id`.
    fn interim_transcript_hash<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        InterimTranscriptHash: traits::InterimTranscriptHash<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<InterimTranscriptHash>, Self::PublicError> {
        self.read_payload(group_id, DataType::InterimTranscriptHash)
    }

    /// Returns the confirmation tag for the group with group id `group_id`.
    fn confirmation_tag<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ConfirmationTag: traits::ConfirmationTag<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<ConfirmationTag>, Self::PublicError> {
        self.read_payload(group_id, DataType::ConfirmationTag)
    }

    /// Deletes the tree from storage
    fn delete_tree<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::PublicError> {
        self.delete_payload(group_id, DataType::TreeSync)
    }

    /// Deletes the confirmation tag from storage
    fn delete_confirmation_tag<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::PublicError> {
        self.delete_payload(group_id, DataType::ConfirmationTag)
    }

    /// Deletes the group context for the group with given id
    fn delete_context<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::PublicError> {
        self.delete_payload(group_id, DataType::Context)
    }

    /// Deletes the interim transcript hash for the group with given id
    fn delete_interim_transcript_hash<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::PublicError> {
        self.delete_payload(group_id, DataType::InterimTranscriptHash)
    }

    /// Removes an individual proposal from the proposal queue of the group with the provided id
    fn remove_proposal<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        proposal_ref: &ProposalRef,
    ) -> Result<(), Self::PublicError> {
        let group_id_bytes = C::to_vec(group_id)?;
        let proposal_ref_bytes = C::to_vec(proposal_ref)?;
        let mut group_states = self.group_states.write().unwrap();
        if let Some(public_group_state) = group_states.get_mut(&group_id_bytes) {
            public_group_state
                .proposal_queue
                .remove(&proposal_ref_bytes);
            if public_group_state.is_empty() {
                group_states.remove(&group_id_bytes);
            }
        }
        Ok(())
    }

    /// Clear the proposal queue for the group with the given id.
    fn clear_proposal_queue<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::PublicError> {
        let group_id_bytes = C::to_vec(group_id)?;
        let mut group_states = self.group_states.write().unwrap();
        if let Some(public_group_state) = group_states.get_mut(&group_id_bytes) {
            public_group_state.proposal_queue.clear();
            if public_group_state.is_empty() {
                group_states.remove(&group_id_bytes);
            }
        }
        Ok(())
    }
}

#[derive(Default, Serialize, Deserialize)]
struct SerializableMlsAssistMemoryStorage {
    storage_bytes: Vec<(Vec<u8>, Vec<u8>)>,
    past_group_states_bytes: Vec<(Vec<u8>, Vec<u8>)>,
    group_infos_bytes: Vec<(Vec<u8>, Vec<u8>)>,
}

impl<C: Codec> MlsAssistMemoryStorage<C> {
    pub fn serialize(&self) -> Result<Vec<u8>, C::Error> {
        let storage = self.group_states.read().unwrap();
        let storage_bytes = storage
            .iter()
            .map(|(key, value)| Ok((key.clone(), C::to_vec(value)?)))
            .collect::<Result<Vec<_>, _>>()?;
        let past_group_states_bytes = self
            .past_group_states
            .read()
            .unwrap()
            .iter()
            .map(|(group_id_bytes, past_group_states_bytes)| {
                (group_id_bytes.clone(), past_group_states_bytes.clone())
            })
            .collect();
        let group_infos_bytes = self
            .group_infos
            .read()
            .unwrap()
            .iter()
            .map(|(group_id_bytes, group_info_bytes)| {
                (group_id_bytes.clone(), group_info_bytes.clone())
            })
            .collect();
        let serialized = SerializableMlsAssistMemoryStorage {
            storage_bytes,
            past_group_states_bytes,
            group_infos_bytes,
        };
        C::to_vec(&serialized)
    }

    pub fn deserialize(serialized: &[u8]) -> Result<Self, C::Error> {
        let deserialized: SerializableMlsAssistMemoryStorage = C::from_slice(serialized)?;
        let past_group_states =
            RwLock::new(deserialized.past_group_states_bytes.into_iter().collect());
        let group_infos = RwLock::new(deserialized.group_infos_bytes.into_iter().collect());
        let storage = Self {
            group_states: RwLock::new(
                deserialized
                    .storage_bytes
                    .into_iter()
                    .map(|(k, v)| Ok((k, C::from_slice(&v)?)))
                    .collect::<Result<HashMap<_, _>, _>>()?,
            ),
            past_group_states,
            group_infos,
            _codec: PhantomData,
        };
        Ok(storage)
    }
}

impl<C: Codec> MlsAssistStorageProvider for MlsAssistMemoryStorage<C> {
    fn write_past_group_states(
        &self,
        group_id: &impl GroupId<CURRENT_VERSION>,
        past_group_states: &impl serde::Serialize,
    ) -> Result<(), StorageError<Self>> {
        let group_id_bytes = C::to_vec(group_id)?;
        let past_group_states_bytes = C::to_vec(past_group_states)?;
        let mut past_group_states = self.past_group_states.write().unwrap();
        past_group_states.insert(group_id_bytes, past_group_states_bytes);
        Ok(())
    }

    fn read_past_group_states<PastGroupStates: DeserializeOwned>(
        &self,
        group_id: &impl GroupId<CURRENT_VERSION>,
    ) -> Result<Option<PastGroupStates>, StorageError<Self>> {
        let group_id_bytes = C::to_vec(group_id)?;
        let past_group_states = self.past_group_states.read().unwrap();
        let Some(past_group_states_bytes) = past_group_states.get(&group_id_bytes) else {
            return Ok(None);
        };
        C::from_slice(past_group_states_bytes).map(Some)
    }

    fn delete_group_info(
        &self,
        group_id: &impl GroupId<CURRENT_VERSION>,
    ) -> Result<(), StorageError<Self>> {
        let group_id_bytes = C::to_vec(group_id)?;
        let mut group_infos = self.group_infos.write().unwrap();
        group_infos.remove(&group_id_bytes);
        Ok(())
    }

    fn write_group_info(
        &self,
        group_id: &impl GroupId<CURRENT_VERSION>,
        group_info: &impl serde::Serialize,
    ) -> Result<(), StorageError<Self>> {
        let group_id_bytes = C::to_vec(group_id)?;
        let group_info_bytes = C::to_vec(group_info)?;
        let mut group_infos = self.group_infos.write().unwrap();
        group_infos.insert(group_id_bytes, group_info_bytes);
        Ok(())
    }

    fn read_group_info<GroupInfo: DeserializeOwned>(
        &self,
        group_id: &impl GroupId<CURRENT_VERSION>,
    ) -> Result<Option<GroupInfo>, StorageError<Self>> {
        let group_id_bytes = C::to_vec(group_id)?;
        let group_infos = self.group_infos.read().unwrap();
        let Some(group_info_bytes) = group_infos.get(&group_id_bytes) else {
            return Ok(None);
        };
        C::from_slice(group_info_bytes).map(Some)
    }

    fn delete_past_group_states(
        &self,
        group_id: &impl GroupId<CURRENT_VERSION>,
    ) -> Result<(), StorageError<Self>> {
        let group_id_bytes = C::to_vec(group_id)?;
        let mut past_group_states = self.past_group_states.write().unwrap();
        past_group_states.remove(&group_id_bytes);
        Ok(())
    }
}

#[derive(Default)]
pub struct MlsAssistRustCrypto<C: Codec> {
    crypto: RustCrypto,
    storage: MlsAssistMemoryStorage<C>,
}

impl<C: Codec> From<MlsAssistMemoryStorage<C>> for MlsAssistRustCrypto<C> {
    fn from(storage: MlsAssistMemoryStorage<C>) -> Self {
        Self {
            crypto: RustCrypto::default(),
            storage,
        }
    }
}

impl<C: Codec> MlsAssistProvider for MlsAssistRustCrypto<C> {
    type Crypto = RustCrypto;

    type Rand = RustCrypto;

    type Storage = MlsAssistMemoryStorage<C>;

    fn storage(&self) -> &Self::Storage {
        &self.storage
    }

    fn crypto(&self) -> &Self::Crypto {
        &self.crypto
    }

    fn rand(&self) -> &Self::Rand {
        &self.crypto
    }
}
