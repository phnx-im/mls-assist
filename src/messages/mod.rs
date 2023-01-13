use openmls::prelude::MlsMessageIn;
use crate::group::GroupInfo;

mod commit;
mod proposals;
pub mod assisted_messages;

pub struct MlsPlaintext;

impl From<MlsMessageIn> for MlsPlaintext {
    fn from(mls_plaintext: MlsMessageIn) -> Self {
        Self {

        }
    }
}
