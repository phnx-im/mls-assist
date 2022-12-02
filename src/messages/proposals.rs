//! # Proposals
//!
//! This module defines all the different types of Proposals.
//!
//! To find out if a specific proposal type is supported,
//! [`ProposalType::is_supported()`] can be used.

use crate::{
    //ciphersuite::hash_ref::{make_proposal_ref, KeyPackageRef, ProposalRef},
    //error::LibraryError,
    //extensions::Extension,
    group::GroupId,
    key_packages::*,
    pool::{Ciphersuite, Extension, LibraryError, ProtocolVersion},
    //versions::ProtocolVersion,
    psks::PreSharedKeyId,
};

use openmls_traits::OpenMlsCryptoProvider;
//use openmls_traits::{types::Ciphersuite, OpenMlsCryptoProvider};
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
use tls_codec::{TlsDeserialize, TlsSerialize, TlsSize, VLBytes};

// Public types

/// ## MLS Proposal Types
///
/// | Value            | Name                     | Recommended | Reference |
/// |:=================|:=========================|:============|:==========|
/// | 0x0000           | RESERVED                 | N/A         | RFC XXXX  |
/// | 0x0001           | add                      | Y           | RFC XXXX  |
/// | 0x0002           | update                   | Y           | RFC XXXX  |
/// | 0x0003           | remove                   | Y           | RFC XXXX  |
/// | 0x0004           | psk                      | Y           | RFC XXXX  |
/// | 0x0005           | reinit                   | Y           | RFC XXXX  |
/// | 0x0006           | external_init            | Y           | RFC XXXX  |
/// | 0x0007           | app_ack                  | Y           | RFC XXXX  |
/// | 0xff00  - 0xffff | Reserved for Private Use | N/A         | RFC XXXX  |
#[derive(
    PartialEq, Eq, Clone, Copy, Debug, TlsSerialize, TlsDeserialize, TlsSize, Serialize, Deserialize,
)]
#[repr(u16)]
#[allow(missing_docs)]
pub enum ProposalType {
    Add = 1,
    Update = 2,
    Remove = 3,
    Presharedkey = 4,
    Reinit = 5,
    ExternalInit = 6,
    AppAck = 7,
    GroupContextExtensions = 8,
}

impl ProposalType {
    /// Check whether a proposal type is supported or not. Returns `true`
    /// if a proposal is supported and `false` otherwise.
    pub fn is_supported(&self) -> bool {
        match self {
            ProposalType::Add
            | ProposalType::Update
            | ProposalType::Remove
            | ProposalType::Presharedkey
            | ProposalType::Reinit
            | ProposalType::ExternalInit => true,
            ProposalType::AppAck => false,
            ProposalType::GroupContextExtensions => true,
        }
    }
}

impl TryFrom<u16> for ProposalType {
    type Error = &'static str;
    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(ProposalType::Add),
            2 => Ok(ProposalType::Update),
            3 => Ok(ProposalType::Remove),
            4 => Ok(ProposalType::Presharedkey),
            5 => Ok(ProposalType::Reinit),
            6 => Ok(ProposalType::ExternalInit),
            7 => Ok(ProposalType::AppAck),
            8 => Ok(ProposalType::GroupContextExtensions),
            _ => Err("Unknown proposal type."),
        }
    }
}

/// Proposal.
///
/// This `enum` contains the different proposals in its variants.
///
/// ```c
/// // draft-ietf-mls-protocol-16
///
/// struct {
///     ProposalType msg_type;
///     select (Proposal.msg_type) {
///         case add:                      Add;
///         case update:                   Update;
///         case remove:                   Remove;
///         case psk:                      PreSharedKey;
///         case reinit:                   ReInit;
///         case external_init:            ExternalInit;
///         case group_context_extensions: GroupContextExtensions;
///     };
/// } Proposal;
/// ```
#[allow(clippy::large_enum_variant)]
#[derive(
    Debug, PartialEq, Clone, Serialize, Deserialize, TlsSerialize, TlsDeserialize, TlsSize,
)]
#[allow(missing_docs)]
#[repr(u8)]
pub enum Proposal {
    Add(AddProposal),
    Update(UpdateProposal),
    Remove(RemoveProposal),
    PreSharedKey(PreSharedKeyProposal),
    ReInit(ReInitProposal),
    ExternalInit(ExternalInitProposal),
    GroupContextExtensions(GroupContextExtensionProposal),
}

impl Proposal {
    pub(crate) fn proposal_type(&self) -> ProposalType {
        match self {
            Self::Add(ref _a) => ProposalType::Add,
            Self::Update(ref _u) => ProposalType::Update,
            Self::Remove(ref _r) => ProposalType::Remove,
            Self::PreSharedKey(ref _p) => ProposalType::Presharedkey,
            Self::ReInit(ref _r) => ProposalType::Reinit,
            Self::ExternalInit(ref _r) => ProposalType::ExternalInit,
            Self::GroupContextExtensions(ref _r) => ProposalType::GroupContextExtensions,
        }
    }

    pub(crate) fn is_type(&self, proposal_type: ProposalType) -> bool {
        self.proposal_type() == proposal_type
    }

    /// Indicates whether a Commit containing this [Proposal] requires a path.
    pub fn is_path_required(&self) -> bool {
        match self {
            Self::Add(_) | Self::PreSharedKey(_) | Self::ReInit(_) => false,
            Self::Update(_)
            | Self::Remove(_)
            | Self::ExternalInit(_)
            | Self::GroupContextExtensions(_) => true,
        }
    }
}

/// Add Proposal.
///
/// An Add proposal requests that a client with a specified KeyPackage be added to the group.
#[derive(
    Debug, PartialEq, Eq, Clone, Serialize, Deserialize, TlsSerialize, TlsDeserialize, TlsSize,
)]
pub struct AddProposal {
    pub(crate) key_package: KeyPackage,
}

impl AddProposal {
    /// Returns a reference to the key package in the proposal.
    pub fn key_package(&self) -> &KeyPackage {
        &self.key_package
    }
}

/// Update Proposal.
///
/// An Update proposal is a similar mechanism to Add with the distinction that it is the
/// sender's leaf KeyPackage in the tree which would be updated with a new KeyPackage.
#[derive(
    Debug, PartialEq, Eq, Clone, Serialize, Deserialize, TlsDeserialize, TlsSerialize, TlsSize,
)]
pub struct UpdateProposal {
    pub(crate) key_package: KeyPackage,
}

impl UpdateProposal {
    /// Returns a reference to the key package in the proposal.
    pub fn key_package(&self) -> &KeyPackage {
        &self.key_package
    }
}

/// Remove Proposal.
///
/// A Remove proposal requests that the member with KeyPackageRef removed be removed from the group.
#[derive(
    Debug, PartialEq, Eq, Clone, Serialize, Deserialize, TlsDeserialize, TlsSerialize, TlsSize,
)]
pub struct RemoveProposal {
    pub(crate) removed: u32,
}

impl RemoveProposal {
    /// Returns the leaf index of the removed leaf in this proposal.
    pub fn removed(&self) -> u32 {
        self.removed
    }
}

/// Preshared Key Proposal.
#[derive(
    Debug, PartialEq, Eq, Clone, Serialize, Deserialize, TlsDeserialize, TlsSerialize, TlsSize,
)]
pub struct PreSharedKeyProposal {
    psk: PreSharedKeyId,
}

impl PreSharedKeyProposal {
    /// Create a new PSK proposal
    #[cfg(any(feature = "test-utils", test))]
    pub(crate) fn new(psk: PreSharedKeyId) -> Self {
        Self { psk }
    }

    /// Returns a reference to the [`PreSharedKeyId`] in this proposal.
    pub(crate) fn _psk(&self) -> &PreSharedKeyId {
        &self.psk
    }

    /// Returns the [`PreSharedKeyId`] and consume this proposal.
    pub(crate) fn into_psk_id(self) -> PreSharedKeyId {
        self.psk
    }
}

/// ReInit proposal.
///
/// This is used to re-initialize a group.
#[derive(
    Debug, PartialEq, Eq, Clone, Serialize, Deserialize, TlsDeserialize, TlsSerialize, TlsSize,
)]
pub struct ReInitProposal {
    pub(crate) group_id: GroupId,
    pub(crate) version: ProtocolVersion,
    pub(crate) ciphersuite: Ciphersuite,
    pub(crate) extensions: Vec<Extension>,
}

/// ExternalInit Proposal.
///
/// This proposal is used for External Commits only.
#[derive(
    Debug, PartialEq, Eq, Clone, Serialize, Deserialize, TlsDeserialize, TlsSerialize, TlsSize,
)]
pub struct ExternalInitProposal {
    kem_output: VLBytes,
}

impl From<Vec<u8>> for ExternalInitProposal {
    fn from(kem_output: Vec<u8>) -> Self {
        ExternalInitProposal {
            kem_output: kem_output.into(),
        }
    }
}

/// ## Group Context Extensions Proposal
///
/// A GroupContextExtensions proposal is used to update the list of extensions
/// in the GroupContext for the group.
///
/// ```text
/// struct { Extension extensions<V>; } GroupContextExtensions;
/// ```
#[derive(
    Debug, PartialEq, Eq, Clone, Serialize, Deserialize, TlsDeserialize, TlsSerialize, TlsSize,
)]
pub struct GroupContextExtensionProposal {
    extensions: Vec<Extension>,
}

impl GroupContextExtensionProposal {
    /// Create a new [`GroupContextExtensionProposal`].
    #[cfg(test)]
    pub(crate) fn new(extensions: &[Extension]) -> Self {
        Self {
            extensions: extensions.into(),
        }
    }
}

// Crate-only types

/// 11.2 Commit
///
/// enum {
///   reserved(0),
///   proposal(1)
///   reference(2),
///   (255)
/// } ProposalOrRefType;
///
/// struct {
///   ProposalOrRefType type;
///   select (ProposalOrRef.type) {
///     case proposal:  Proposal proposal;
///     case reference: opaque hash<0..255>;
///   }
/// } ProposalOrRef;
///
/// Type of Proposal, either by value or by reference
/// We only implement the values (1, 2), other values are not valid
/// and will yield `ProposalOrRefTypeError::UnknownValue` when decoded.
#[derive(
    PartialEq, Clone, Copy, Debug, TlsSerialize, TlsDeserialize, TlsSize, Serialize, Deserialize,
)]
#[repr(u8)]
pub(crate) enum ProposalOrRefType {
    Proposal = 1,
    Reference = 2,
}

/// Type of Proposal, either by value or by reference.
#[derive(
    Debug, PartialEq, Clone, Serialize, Deserialize, TlsSerialize, TlsDeserialize, TlsSize,
)]
#[repr(u8)]
#[allow(missing_docs)]
pub(crate) enum ProposalOrRef {
    #[tls_codec(discriminant = 1)]
    Proposal(Proposal),
    Reference(ProposalRef),
}

impl ProposalRef {
    pub(crate) fn from_proposal(
        ciphersuite: Ciphersuite,
        backend: &impl OpenMlsCryptoProvider,
        proposal: &Proposal,
    ) -> Result<Self, LibraryError> {
        /* let encoded = proposal
            .tls_serialize_detached()
            .map_err(LibraryError::missing_bound_check)?;

        make_proposal_ref(&encoded, ciphersuite, backend.crypto())
            .map_err(LibraryError::unexpected_crypto_error) */
        unimplemented!()
    }
}

#[derive(
    Debug, PartialEq, Clone, Serialize, Deserialize, TlsSerialize, TlsDeserialize, TlsSize,
)]
pub(crate) struct ProposalRef;
