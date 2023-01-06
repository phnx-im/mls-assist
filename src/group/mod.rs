use serde::{Deserialize, Serialize};
use tls_codec::{TlsDeserialize, TlsSerialize, TlsSize, VLBytes};

use crate::{
    messages::AssistedMessage,
    pool::{Ciphersuite, Extension, ProtocolVersion},
};

pub mod process;
mod validate_application;
mod validate_commit;
mod validate_proposal;

/// The `LeafNode` struct from Section 7.2 of the MLS specification.
///
/// ```c
/// struct {
///     HPKEPublicKey encryption_key;
///     SignaturePublicKey signature_key;
///     Credential credential;
///     Capabilities capabilities;
///
///     LeafNodeSource leaf_node_source;
///     select (LeafNode.leaf_node_source) {
///         case key_package:
///             Lifetime lifetime;
///
///         case update:
///             struct{};
///
///         case commit:
///             opaque parent_hash<V>;
///     };
///
///     Extension extensions<V>;
///     /* SignWithLabel(., "LeafNodeTBS", LeafNodeTBS) */
///     opaque signature<V>;
/// } LeafNode;
/// ```
pub struct LeafNode {}

pub struct Group {
    group_info: GroupInfo,
}

impl Group {
    /// Create a new group state with the group consisting of the creator's
    /// leaf.
    pub fn new(group_info: GroupInfo, leaf_node: LeafNode) -> Self {
        Self { group_info }
    }

    pub fn merge_staged_commit(&mut self, _staged_commit: StagedCommit) {}

    pub fn public_tree() {}

    pub fn group_info(&self) -> &GroupInfo {
        &self.group_info
    }

    pub fn members() {}
}

#[derive(
    Debug, PartialEq, Eq, Clone, Serialize, Deserialize, TlsDeserialize, TlsSerialize, TlsSize,
)]
pub struct GroupId;

#[derive(
    Debug, PartialEq, Eq, Clone, Copy, Serialize, Deserialize, TlsDeserialize, TlsSerialize, TlsSize,
)]
pub struct GroupEpoch;

#[derive(
    Debug, PartialEq, Eq, Clone, Serialize, Deserialize, TlsDeserialize, TlsSerialize, TlsSize,
)]
pub struct GroupContext {
    protocol_version: ProtocolVersion,
    ciphersuite: Ciphersuite,
    group_id: GroupId,
    epoch: GroupEpoch,
    tree_hash: VLBytes,
    confirmed_transcript_hash: VLBytes,
    extensions: Vec<Extension>,
}

#[derive(
    Debug, PartialEq, Eq, Clone, Serialize, Deserialize, TlsDeserialize, TlsSerialize, TlsSize,
)]
pub struct GroupInfoTBS {
    group_context: GroupContext,
    extensions: Vec<Extension>,
    confirmation_tag: VLBytes,
    signer: u32,
}

#[derive(
    Debug, PartialEq, Eq, Clone, Serialize, Deserialize, TlsDeserialize, TlsSerialize, TlsSize,
)]
pub struct GroupInfo {
    group_info_tbs: GroupInfoTBS,
    signature: VLBytes,
}

pub struct StagedCommit {}
