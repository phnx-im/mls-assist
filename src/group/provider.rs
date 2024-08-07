use openmls::storage::OpenMlsProvider;
use openmls_traits::storage::{traits::GroupId, CURRENT_VERSION};
use serde::{de::DeserializeOwned, Serialize};

use super::errors::StorageError;

/// A storage provider for MLS-assist.
pub trait MlsAssistProvider: OpenMlsProvider {
    fn write_past_group_states(
        &self,
        group_id: &impl GroupId<CURRENT_VERSION>,
        past_group_states: &impl Serialize,
    ) -> Result<(), StorageError<Self>>;

    fn read_past_group_states<PastGroupStates: DeserializeOwned>(
        &self,
        group_id: &impl GroupId<CURRENT_VERSION>,
    ) -> Result<Option<PastGroupStates>, StorageError<Self>>;

    fn write_group_info(
        &self,
        group_id: &impl GroupId<CURRENT_VERSION>,
        group_info: &impl Serialize,
    ) -> Result<(), StorageError<Self>>;

    fn read_group_info<GroupInfo: DeserializeOwned>(
        &self,
        group_id: &impl GroupId<CURRENT_VERSION>,
    ) -> Result<Option<GroupInfo>, StorageError<Self>>;
}
