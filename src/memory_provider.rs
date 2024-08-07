use std::{collections::HashMap, sync::RwLock};

use openmls_rust_crypto::{MemoryStorage, OpenMlsRustCrypto, RustCrypto};
use openmls_traits::{
    storage::{traits::GroupId, CURRENT_VERSION},
    OpenMlsProvider,
};
use serde::de::DeserializeOwned;

use crate::group::{errors::StorageError, provider::MlsAssistProvider};

pub struct MlsAssistRustCrypto {
    openmls_provider: OpenMlsRustCrypto,
    past_group_states: RwLock<HashMap<Vec<u8>, Vec<u8>>>,
    group_infos: RwLock<HashMap<Vec<u8>, Vec<u8>>>,
}

impl OpenMlsProvider for MlsAssistRustCrypto {
    type CryptoProvider = RustCrypto;

    type RandProvider = RustCrypto;

    type StorageProvider = MemoryStorage;

    fn storage(&self) -> &Self::StorageProvider {
        self.openmls_provider.storage()
    }

    fn crypto(&self) -> &Self::CryptoProvider {
        self.openmls_provider.crypto()
    }

    fn rand(&self) -> &Self::RandProvider {
        self.openmls_provider.rand()
    }
}

impl MlsAssistProvider for MlsAssistRustCrypto {
    fn write_past_group_states(
        &self,
        group_id: &impl GroupId<CURRENT_VERSION>,
        past_group_states: &impl serde::Serialize,
    ) -> Result<(), StorageError<Self>> {
        let group_id_bytes = serde_json::to_vec(group_id)?;
        let past_group_states_bytes = serde_json::to_vec(past_group_states)?;
        let mut past_group_states = self.past_group_states.write().unwrap();
        past_group_states.insert(group_id_bytes, past_group_states_bytes);
        Ok(())
    }

    fn read_past_group_states<PastGroupStates: DeserializeOwned>(
        &self,
        group_id: &impl GroupId<CURRENT_VERSION>,
    ) -> Result<Option<PastGroupStates>, StorageError<Self>> {
        let group_id_bytes = serde_json::to_vec(group_id)?;
        let past_group_states = self.past_group_states.read().unwrap();
        let Some(past_group_states_bytes) = past_group_states.get(&group_id_bytes) else {
            return Ok(None);
        };
        serde_json::from_slice(&past_group_states_bytes)
            .map(Some)
            .map_err(StorageError::<Self>::from)
    }

    fn write_group_info(
        &self,
        group_id: &impl GroupId<CURRENT_VERSION>,
        group_info: &impl serde::Serialize,
    ) -> Result<(), StorageError<Self>> {
        let group_id_bytes = serde_json::to_vec(group_id)?;
        let group_info_bytes = serde_json::to_vec(group_info)?;
        let mut group_infos = self.group_infos.write().unwrap();
        group_infos.insert(group_id_bytes, group_info_bytes);
        Ok(())
    }

    fn read_group_info<GroupInfo: DeserializeOwned>(
        &self,
        group_id: &impl GroupId<CURRENT_VERSION>,
    ) -> Result<Option<GroupInfo>, StorageError<Self>> {
        let group_id_bytes = serde_json::to_vec(group_id)?;
        let group_infos = self.group_infos.read().unwrap();
        let Some(group_info_bytes) = group_infos.get(&group_id_bytes) else {
            return Ok(None);
        };
        serde_json::from_slice(&group_info_bytes)
            .map(Some)
            .map_err(StorageError::<Self>::from)
    }
}
