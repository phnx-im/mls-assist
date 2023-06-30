use openmls::{
    prelude::{MlsMessageIn, MlsMessageInBody, MlsMessageOut, ProtocolMessage, WireFormat},
    versions::ProtocolVersion,
};
use tls_codec::{Deserialize, DeserializeBytes, Serialize, Size};

use super::{AssistedGroupInfoIn, AssistedMessageIn, AssistedWelcome};

impl Size for AssistedMessageIn {
    fn tls_serialized_len(&self) -> usize {
        ProtocolVersion::default().tls_serialized_len()
            + match &self.mls_message {
                ProtocolMessage::PrivateMessage(pm) => {
                    WireFormat::PrivateMessage.tls_serialized_len() + pm.tls_serialized_len()
                }
                ProtocolMessage::PublicMessage(pm) => {
                    WireFormat::PublicMessage.tls_serialized_len() + pm.tls_serialized_len()
                }
            }
            + self.group_info_option.tls_serialized_len()
    }
}

impl DeserializeBytes for AssistedMessageIn {
    fn tls_deserialize(bytes: &[u8]) -> Result<(Self, &[u8]), tls_codec::Error>
    where
        Self: Sized,
    {
        let (mls_message, remainder) = <MlsMessageIn as DeserializeBytes>::tls_deserialize(bytes)?;
        let mut remainder_reader = remainder;
        let group_info_option =
            Option::<AssistedGroupInfoIn>::tls_deserialize(&mut remainder_reader)?;
        let serialized_mls_message = bytes
            .get(..bytes.len() - remainder.len())
            .ok_or(tls_codec::Error::EndOfStream)?
            .to_vec();
        let remainder = remainder
            .get(group_info_option.tls_serialized_len()..)
            .ok_or(tls_codec::Error::EndOfStream)?;
        let mls_message = match mls_message.extract() {
            MlsMessageInBody::PublicMessage(pm) => pm.into(),
            MlsMessageInBody::PrivateMessage(pm) => pm.into(),
            MlsMessageInBody::Welcome(_)
            | MlsMessageInBody::GroupInfo(_)
            | MlsMessageInBody::KeyPackage(_) => return Err(tls_codec::Error::InvalidInput),
        };

        let assisted_message = Self {
            mls_message,
            serialized_mls_message: super::SerializedMlsMessage(serialized_mls_message),
            group_info_option,
        };
        Ok((assisted_message, remainder))
    }
}

impl Size for AssistedWelcome {
    fn tls_serialized_len(&self) -> usize {
        MlsMessageOut::from_welcome(self.welcome.clone(), ProtocolVersion::default())
            .tls_serialized_len()
        //// Any version
        //ProtocolVersion::default().tls_serialized_len() +
        //// Any wire format
        //WireFormat::PublicMessage.tls_serialized_len() +
        //// The welcome
        //self.welcome.tls_serialized_len()
    }
}

impl Serialize for AssistedWelcome {
    fn tls_serialize<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        MlsMessageOut::from_welcome(self.welcome.clone(), ProtocolVersion::default())
            .tls_serialize(writer)
    }
}

impl Deserialize for AssistedWelcome {
    fn tls_deserialize<R: std::io::Read>(bytes: &mut R) -> Result<Self, tls_codec::Error>
    where
        Self: Sized,
    {
        let mls_message = <MlsMessageIn as Deserialize>::tls_deserialize(bytes)?;
        match mls_message.extract() {
            MlsMessageInBody::Welcome(welcome) => Ok(AssistedWelcome { welcome }),
            _ => Err(tls_codec::Error::InvalidInput),
        }
    }
}

impl DeserializeBytes for AssistedWelcome {
    fn tls_deserialize(bytes: &[u8]) -> Result<(Self, &[u8]), tls_codec::Error>
    where
        Self: Sized,
    {
        let (mls_message, remainder) = <MlsMessageIn as DeserializeBytes>::tls_deserialize(bytes)?;
        match mls_message.extract() {
            MlsMessageInBody::Welcome(welcome) => Ok((AssistedWelcome { welcome }, remainder)),
            _ => Err(tls_codec::Error::EndOfStream),
        }
    }
}
