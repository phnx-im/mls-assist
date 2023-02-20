use openmls::prelude::{LibraryError, ProcessMessageError};
use thiserror::Error;

#[cfg(doc)]
use openmls::prelude::{group_info::GroupInfo, GroupContext, ProcessedMessage};

/// Process message error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum ProcessAssistedMessageError {
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    /// Invalid group info signature.
    #[error("Invalid group info signature.")]
    InvalidGroupInfoSignature,
    /// The message's wire format is incompatible with the group's wire format policy.
    #[error("The message's wire format is incompatible with the group's wire format policy.")]
    IncompatibleWireFormat,
    /// See [`ProcessMessageError`] for more details.
    #[error(transparent)]
    ProcessMessageError(#[from] ProcessMessageError),
    /// Unknown sender.
    #[error("Unknown sender.")]
    UnknownSender,
    /// [`GroupContext`] is inconsistent between [`ProcessedMessage`] and [`GroupInfo`].
    #[error("[`GroupContext`] is inconsistent between [`ProcessedMessage`] and [`GroupInfo`].")]
    InconsistentGroupContext,
}
