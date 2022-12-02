use crate::group::GroupInfo;

mod commit;
mod proposals;

pub struct MlsPlaintext;

pub enum AssistedMessage {
    Commit(AssistedCommit),
    NonCommit(MlsPlaintext),
}

pub struct AssistedCommit {
    commit: MlsPlaintext,
    assisted_group_info: AssistedGroupInfo,
}

pub enum AssistedGroupInfo {
    Full(GroupInfo),
    Signature(Vec<u8>),
}
