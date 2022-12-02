use serde::{Deserialize, Serialize};
use tls_codec::*;

use super::proposals::ProposalOrRef;

/// Commit.
///
/// A Commit message initiates a new epoch for the group,
/// based on a collection of Proposals. It instructs group
/// members to update their representation of the state of
/// the group by applying the proposals and advancing the
/// key schedule.
///
/// ```c
/// // draft-ietf-mls-protocol-16
///
/// struct {
///     ProposalOrRef proposals<V>;
///     optional<UpdatePath> path;
/// } Commit;
/// ```
#[derive(
    Debug, PartialEq, Clone, Serialize, Deserialize, TlsDeserialize, TlsSerialize, TlsSize,
)]
pub(crate) struct Commit {
    pub(crate) proposals: Vec<ProposalOrRef>,
    pub(crate) path: Option<UpdatePath>,
}

#[derive(
    Debug, PartialEq, Clone, Serialize, Deserialize, TlsDeserialize, TlsSerialize, TlsSize,
)]
pub(crate) struct UpdatePath;
