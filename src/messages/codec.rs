use openmls::{
    framing::WireFormat,
    prelude::{ContentType, MlsMessageIn, MlsMessageInBody, ProtocolMessage},
    versions::ProtocolVersion,
};
use tls_codec::{Deserialize, DeserializeBytes, Serialize, Size};

use super::{AssistedCommit, AssistedGroupInfoIn, AssistedMessage, AssistedWelcome};

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
                    let assisted_group_info = AssistedGroupInfoIn::tls_deserialize(bytes)?;
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

impl DeserializeBytes for AssistedMessage {
    fn tls_deserialize(bytes: &[u8]) -> Result<(Self, &[u8]), tls_codec::Error>
    where
        Self: Sized,
    {
        let mut bytes_reader = bytes;
        let assisted_message = <Self as Deserialize>::tls_deserialize(&mut bytes_reader)?;
        let remainder = bytes
            .get(assisted_message.tls_serialized_len()..)
            .ok_or(tls_codec::Error::EndOfStream)?;
        Ok((assisted_message, remainder))
    }
}

impl Size for AssistedWelcome {
    fn tls_serialized_len(&self) -> usize {
        // Any version
        ProtocolVersion::default().tls_serialized_len() +
        // Any wire format
        WireFormat::PublicMessage.tls_serialized_len() +
        // The welcome
        self.welcome.tls_serialized_len()
    }
}

impl Serialize for AssistedWelcome {
    fn tls_serialize<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        // Default version
        let mut written = ProtocolVersion::default().tls_serialize(writer)?;
        // Any wire format
        written += WireFormat::Welcome.tls_serialize(writer)?;
        // The welcome
        self.welcome.tls_serialize(writer).map(|l| written + l)
    }
}

impl DeserializeBytes for AssistedWelcome {
    fn tls_deserialize(bytes: &[u8]) -> Result<(Self, &[u8]), tls_codec::Error>
    where
        Self: Sized,
    {
        let mut bytes_reader = bytes;
        let mls_message = MlsMessageIn::tls_deserialize(&mut bytes_reader)?;
        let remainder = bytes
            .get(mls_message.tls_serialized_len()..)
            .ok_or(tls_codec::Error::EndOfStream)?;
        match mls_message.extract() {
            MlsMessageInBody::Welcome(welcome) => Ok((AssistedWelcome { welcome }, remainder)),
            _ => Err(tls_codec::Error::InvalidInput),
        }
    }
}
