use openmls::{
    framing::PublicMessage,
    prelude::{
        group_info::VerifiableGroupInfo, ConfirmationTag, Extensions, GroupContext, LeafNodeIndex,
        Signature,
    },
};

/// TODO: When deserializing this, make sure it errors out if the message type
/// doesn't fit.
#[repr(u8)]
pub enum AssistedMessage {
    Commit(AssistedCommit),
    NonCommit(PublicMessage),
}

pub struct AssistedCommit {
    pub commit: PublicMessage,
    pub assisted_group_info: AssistedGroupInfo,
}

#[repr(u8)]
pub enum AssistedGroupInfo {
    Full(VerifiableGroupInfo),
    SignatureAndExtensions((Signature, Extensions)),
}

impl AssistedGroupInfo {
    pub fn into_verifiable_group_info(
        self,
        sender_index: LeafNodeIndex,
        group_context: GroupContext,
        confirmation_tag: ConfirmationTag,
    ) -> VerifiableGroupInfo {
        match self {
            AssistedGroupInfo::Full(group_info) => group_info,
            AssistedGroupInfo::SignatureAndExtensions((signature, extensions)) => {
                VerifiableGroupInfo::new(
                    group_context,
                    extensions,
                    confirmation_tag,
                    sender_index,
                    signature,
                )
            }
        }
    }
}
