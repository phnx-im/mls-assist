use openmls::prelude::ProcessMessageError;
use openmls_traits::{
    storage::StorageProvider as StorageProviderTrait, storage::CURRENT_VERSION, OpenMlsProvider,
};
use thiserror::Error;

#[cfg(doc)]
use openmls::prelude::{group_info::GroupInfo, GroupContext, ProcessedMessage};

pub type StorageError<Provider> =
    <<Provider as OpenMlsProvider>::StorageProvider as StorageProviderTrait<CURRENT_VERSION>>::Error;

/// Process message error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum ProcessAssistedMessageError<StorageError> {
    /// Invalid assisted message.
    #[error("Invalid assisted message.")]
    InvalidAssistedMessage,
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    /// Invalid group info signature.
    #[error("Invalid group info signature.")]
    InvalidGroupInfoSignature,
    /// Invalid group info message.
    #[error("Invalid group info message.")]
    InvalidGroupInfoMessage,
    /// See [`ProcessMessageError`] for more details.
    #[error(transparent)]
    ProcessMessageError(#[from] ProcessMessageError<StorageError>),
    /// Unknown sender.
    #[error("Unknown sender.")]
    UnknownSender,
    /// [`GroupContext`] is inconsistent between [`ProcessedMessage`] and [`GroupInfo`].
    #[error("[`GroupContext`] is inconsistent between [`ProcessedMessage`] and [`GroupInfo`].")]
    InconsistentGroupContext,
}

#[derive(Error, Debug, PartialEq, Clone)]
pub enum LibraryError {
    /// See [`LibraryError`] for more details.
    #[error("Error in the implementation of this Library.")]
    LibraryError,
    #[error(transparent)]
    OpenMlsLibraryError(#[from] openmls::prelude::LibraryError),
}
