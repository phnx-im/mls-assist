use openmls::{
    framing::WireFormat,
    prelude::{ContentType, MlsMessageIn, MlsMessageInBody, ProtocolMessage},
    versions::ProtocolVersion,
};
use tls_codec::{Deserialize, Size};

use super::{AssistedCommit, AssistedGroupInfo, AssistedMessage};

impl Size for AssistedMessage {
    fn tls_serialized_len(&self) -> usize {
        match self {
            AssistedMessage::Commit(c) => {
                // First the commit
                // Any version
                ProtocolVersion::default().tls_serialized_len()
                    + WireFormat::PublicMessage.tls_serialized_len()
                    + c.commit.tls_serialized_len()
                    + c.assisted_group_info.tls_serialized_len()
            }
            AssistedMessage::NonCommit(nc) => {
                // Any version
                ProtocolVersion::default().tls_serialized_len() +
                // Any wire format
                WireFormat::PublicMessage.tls_serialized_len() +
                match nc {
                    ProtocolMessage::PrivateMessage(pm) => pm.tls_serialized_len(),
                    ProtocolMessage::PublicMessage(pm) => pm.tls_serialized_len(),
                }
            }
        }
    }
}

impl Deserialize for AssistedMessage {
    fn tls_deserialize<R: std::io::Read>(bytes: &mut R) -> Result<Self, tls_codec::Error>
    where
        Self: Sized,
    {
        // First deserialize the main message.
        let mls_message = MlsMessageIn::tls_deserialize(bytes)?;
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
                    let assisted_group_info = AssistedGroupInfo::tls_deserialize(bytes)?;
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
