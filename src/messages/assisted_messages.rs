use openmls::prelude::GroupInfo;
use crate::messages::MlsPlaintext;
use openmls::framing::PublicMessage;

pub enum AssistedMessage {
    Commit(AssistedCommit),
    NonCommit(PublicMessage),
}

impl AssistedCommit {
    fn new(mls_plaintext: PublicMessage, group_info: AssistedGroupInfo) -> Self {
        Self {
            commit: mls_plaintext,
            assisted_group_info: group_info,
        }
    }
}

pub struct AssistedCommit {
    commit: PublicMessage,
    assisted_group_info: AssistedGroupInfo,
}

pub enum AssistedGroupInfo {
    Full(GroupInfo),
    Signature(Vec<u8>),
}