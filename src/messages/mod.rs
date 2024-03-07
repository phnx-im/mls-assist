use openmls::prelude::{
    group_info::VerifiableGroupInfo, ConfirmationTag, Extensions, GroupContext, GroupId,
    KeyPackageRef, LeafNodeIndex, MlsMessageBodyIn, MlsMessageIn, MlsMessageOut, ProtocolMessage,
    Sender, Signature, Welcome,
};
use tls_codec::{TlsDeserialize, TlsSerialize, TlsSize};

pub mod codec;

pub enum DeserializationError {
    InvalidMessage,
    MissingGroupInfo,
}

#[derive(Debug, TlsSerialize, TlsSize)]
pub struct AssistedMessageOut {
    pub mls_message: MlsMessageOut,
    pub group_info_option: Option<AssistedGroupInfo>,
}

#[derive(Debug)]
pub struct AssistedMessageIn {
    pub(crate) mls_message: ProtocolMessage,
    pub(crate) serialized_mls_message: SerializedMlsMessage,
    pub(crate) group_info_option: Option<AssistedGroupInfoIn>,
}

#[derive(Debug)]
pub struct SerializedMlsMessage(pub Vec<u8>);

impl AssistedMessageIn {
    pub fn into_serialized_mls_message(self) -> SerializedMlsMessage {
        self.serialized_mls_message
    }

    pub fn group_id(&self) -> &GroupId {
        self.mls_message.group_id()
    }

    pub fn sender(&self) -> Option<&Sender> {
        match &self.mls_message {
            ProtocolMessage::PrivateMessage(_) => None,
            ProtocolMessage::PublicMessage(pm) => Some(pm.sender()),
        }
    }
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
                if let MlsMessageBodyIn::GroupInfo(group_info) = mls_message_in.extract() {
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
