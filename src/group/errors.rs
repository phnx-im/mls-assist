use openmls::prelude::ProcessMessageError;
use openmls_rust_crypto::MemoryStorageError;
use thiserror::Error;

#[cfg(doc)]
use openmls::prelude::{group_info::GroupInfo, GroupContext, ProcessedMessage};

/// Process message error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum ProcessAssistedMessageError {
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
    ProcessMessageError(#[from] ProcessMessageError<MemoryStorageError>),
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
