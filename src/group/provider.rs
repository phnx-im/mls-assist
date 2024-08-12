use openmls::storage::PublicStorageProvider;
use openmls_traits::{
    crypto::OpenMlsCrypto,
    random::OpenMlsRand,
    storage::{traits::GroupId, CURRENT_VERSION},
};
use serde::{de::DeserializeOwned, Serialize};

use super::errors::StorageError;

/// A storage provider for MLS-assist.
pub trait MlsAssistProvider {
    type Storage: PublicStorageProvider;
    type Crypto: OpenMlsCrypto;
    type Rand: OpenMlsRand;

    fn write_past_group_states(
        &self,
        group_id: &impl GroupId<CURRENT_VERSION>,
        past_group_states: &impl Serialize,
    ) -> Result<(), StorageError<Self::Storage>>;

    fn storage(&self) -> &Self::Storage;

    fn crypto(&self) -> &Self::Crypto;

    fn rand(&self) -> &Self::Rand;

    fn read_past_group_states<PastGroupStates: DeserializeOwned>(
        &self,
        group_id: &impl GroupId<CURRENT_VERSION>,
    ) -> Result<Option<PastGroupStates>, StorageError<Self::Storage>>;

    fn write_group_info(
        &self,
        group_id: &impl GroupId<CURRENT_VERSION>,
        group_info: &impl Serialize,
    ) -> Result<(), StorageError<Self::Storage>>;

    fn read_group_info<GroupInfo: DeserializeOwned>(
        &self,
        group_id: &impl GroupId<CURRENT_VERSION>,
    ) -> Result<Option<GroupInfo>, StorageError<Self::Storage>>;
}
