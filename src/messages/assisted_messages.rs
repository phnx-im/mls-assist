use crate::group::GroupInfo;
use crate::messages::MlsPlaintext;

pub enum AssistedMessage {
    Commit(AssistedCommit),
    NonCommit(MlsPlaintext),
}

impl AssistedCommit {
    fn new(mls_plaintext: PublicMessage, group_info: AssistedGroupInfo) -> Self {
        Self {
            commit: MlsPlaintext,
            assisted_group_info: group_info,
        }
    }
}

pub struct AssistedCommit {
    commit: MlsPlaintext,
    assisted_group_info: AssistedGroupInfo,
}

pub enum AssistedGroupInfo {
    Full(GroupInfo),
    Signature(Vec<u8>),
}