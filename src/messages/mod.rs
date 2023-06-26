use openmls::prelude::{
    group_info::VerifiableGroupInfo, ConfirmationTag, ContentType, Extensions, GroupContext,
    GroupEpoch, GroupId, KeyPackageRef, LeafNodeIndex, MlsMessageIn, MlsMessageInBody,
    MlsMessageOut, ProtocolMessage, PublicMessageIn, Sender, Signature, Welcome,
};
use tls_codec::{Deserialize as TlsDeserializeTrait, TlsDeserialize, TlsSerialize, TlsSize};

pub mod codec;

pub enum DeserializationError {
    InvalidMessage,
    MissingGroupInfo,
}

#[derive(TlsSerialize, TlsDeserialize, TlsSize, Clone)]
pub struct SerializedAssistedMessage {
    mls_message_bytes: Vec<u8>,
    group_info_bytes_option: Option<Vec<u8>>,
}

impl TryInto<AssistedMessage> for &SerializedAssistedMessage {
    type Error = DeserializationError;

    fn try_into(self) -> Result<AssistedMessage, Self::Error> {
        // First deserialize the main message.
        let mls_message = MlsMessageIn::tls_deserialize(&mut self.mls_message_bytes.as_slice())
            .map_err(|_| DeserializationError::InvalidMessage)?;
        // Then check the content message type.
        let assisted_message = match mls_message.extract() {
            // We don't accept Welcomes, GroupInfos or KeyPackages.
            MlsMessageInBody::Welcome(_)
            | MlsMessageInBody::GroupInfo(_)
            | MlsMessageInBody::KeyPackage(_) => return Err(DeserializationError::InvalidMessage),
            // Private messages are Okay, but we can't really do anything with them.
            MlsMessageInBody::PrivateMessage(private_message) => {
                AssistedMessage::NonCommit(private_message.into())
            }
            // We are only able to process public messages
            MlsMessageInBody::PublicMessage(public_message) => {
                if matches!(public_message.content_type(), ContentType::Commit) {
                    let assisted_group_info = AssistedGroupInfoIn::tls_deserialize(
                        &mut self
                            .group_info_bytes_option
                            .as_ref()
                            .ok_or(DeserializationError::MissingGroupInfo)?
                            .as_slice(),
                    )
                    .map_err(|_| DeserializationError::InvalidMessage)?;
                    let assisted_commit = AssistedCommit {
                        commit: public_message,
                        assisted_group_info,
                    };
                    AssistedMessage::Commit(assisted_commit)
                } else {
                    AssistedMessage::NonCommit(public_message.into())
                }
            }
        };
        Ok(assisted_message)
    }
}

/// This enum can be deserialized from either a single MLSMessage (in case of a
/// non-commit message) or an MLSMessage concatenated with a serialized
/// [`AssistedGroupInfo`].
#[derive(Debug, Clone)]
pub enum AssistedMessage {
    Commit(AssistedCommit),
    NonCommit(ProtocolMessage),
}

impl AssistedMessage {
    /// Get the group id associated with this message.
    pub fn group_id(&self) -> &GroupId {
        match self {
            AssistedMessage::Commit(ac) => ac.commit.group_id(),
            AssistedMessage::NonCommit(non_commit) => non_commit.group_id(),
        }
    }

    pub fn epoch(&self) -> GroupEpoch {
        match self {
            AssistedMessage::Commit(ac) => ac.commit.epoch(),
            AssistedMessage::NonCommit(non_commit) => non_commit.epoch(),
        }
    }

    // Returns the sender of the message if the message is a [`PublicMessage`]
    // or `None` if the message is a `PrivateMessage`.
    pub fn sender(&self) -> Option<&Sender> {
        match self {
            AssistedMessage::Commit(c) => c.commit.sender().into(),
            AssistedMessage::NonCommit(nc) => match nc {
                ProtocolMessage::PrivateMessage(_) => None,
                ProtocolMessage::PublicMessage(pm) => pm.sender().into(),
            },
        }
    }

    /// Deserialize the given bytes into an [`AssistedMessage`] and return it,
    /// together with the serialized [`MlsMessage`] part of the
    /// [`AssistedMessage`].
    pub fn try_from_bytes(mut bytes: &[u8]) -> Result<(&[u8], Self), tls_codec::Error> {
        // First deserialize the main message.
        let mls_message = MlsMessageIn::tls_deserialize(&mut bytes)?;
        // If it's a commit, we have to check for the assisted group info.
        let assisted_message = match mls_message.extract() {
            // We don't accept Welcomes, GroupInfos or KeyPackages.
            MlsMessageInBody::Welcome(_)
            | MlsMessageInBody::GroupInfo(_)
            | MlsMessageInBody::KeyPackage(_) => return Err(tls_codec::Error::InvalidInput),
            // Private messages are Okay, but we can't really do anything with them.
            MlsMessageInBody::PrivateMessage(private_message) => {
                AssistedMessage::NonCommit(private_message.into())
            }
            // We are only able to process public messages
            MlsMessageInBody::PublicMessage(public_message) => {
                if matches!(public_message.content_type(), ContentType::Commit) {
                    let assisted_group_info = AssistedGroupInfoIn::tls_deserialize(&mut bytes)?;
                    let assisted_commit = AssistedCommit {
                        commit: public_message,
                        assisted_group_info,
                    };
                    AssistedMessage::Commit(assisted_commit)
                } else {
                    AssistedMessage::NonCommit(public_message.into())
                }
            }
        };
        Ok((bytes, assisted_message))
    }
}

#[derive(Debug, TlsDeserialize, TlsSize, Clone)]
pub struct AssistedCommit {
    pub commit: PublicMessageIn,
    pub assisted_group_info: AssistedGroupInfoIn,
}

#[derive(Debug, TlsSize, Clone, TlsSerialize)]
#[repr(u8)]
pub enum AssistedGroupInfo {
    Full(MlsMessageOut),
    SignatureAndExtensions((Signature, Extensions)),
}

#[derive(Debug, TlsDeserialize, TlsSize, Clone)]
#[repr(u8)]
pub enum AssistedGroupInfoIn {
    Full(MlsMessageIn),
    SignatureAndExtensions((Signature, Extensions)),
}

impl AssistedGroupInfoIn {
    pub fn try_into_verifiable_group_info(
        self,
        sender_index: LeafNodeIndex,
        group_context: GroupContext,
        confirmation_tag: ConfirmationTag,
    ) -> Result<VerifiableGroupInfo, DeserializationError> {
        let group_info = match self {
            AssistedGroupInfoIn::Full(mls_message_in) => {
                if let MlsMessageInBody::GroupInfo(group_info) = mls_message_in.extract() {
                    group_info
                } else {
                    return Err(DeserializationError::InvalidMessage);
                }
            }
            AssistedGroupInfoIn::SignatureAndExtensions((signature, extensions)) => {
                VerifiableGroupInfo::new(
                    group_context,
                    extensions,
                    confirmation_tag,
                    sender_index,
                    signature,
                )
            }
        };
        Ok(group_info)
    }
}

#[derive(Debug, Clone)]
pub struct AssistedWelcome {
    pub welcome: Welcome,
}

impl AssistedWelcome {
    pub fn joiners(&self) -> impl Iterator<Item = KeyPackageRef> + '_ {
        self.welcome
            .secrets()
            .iter()
            .map(|secret| secret.new_member())
    }
}
