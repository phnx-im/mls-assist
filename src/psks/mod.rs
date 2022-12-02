use crate::group::{GroupEpoch, GroupId};
use serde::{Deserialize, Serialize};
use tls_codec::{TlsDeserialize, TlsSerialize, TlsSize, VLBytes};

/// External PSK.
#[derive(
    Debug, PartialEq, Eq, Clone, Hash, Serialize, Deserialize, TlsDeserialize, TlsSerialize, TlsSize,
)]
pub struct ExternalPsk {
    psk_id: VLBytes,
}

impl ExternalPsk {
    /// Create a new `ExternalPsk` from a PSK ID
    pub fn new(psk_id: Vec<u8>) -> Self {
        Self {
            psk_id: psk_id.into(),
        }
    }

    /// Return the PSK ID
    pub fn psk_id(&self) -> &[u8] {
        self.psk_id.as_slice()
    }
}

/// Resumption PSK.
#[derive(
    Debug, PartialEq, Eq, Clone, Serialize, Deserialize, TlsDeserialize, TlsSerialize, TlsSize,
)]
pub struct ResumptionPsk {
    pub(crate) usage: ResumptionPskUsage,
    pub(crate) psk_group_id: GroupId,
    pub(crate) psk_epoch: GroupEpoch,
}

impl ResumptionPsk {
    /// Return the usage
    pub fn usage(&self) -> ResumptionPskUsage {
        self.usage
    }

    /// Return the `GroupId`
    pub fn psk_group_id(&self) -> &GroupId {
        &self.psk_group_id
    }

    /// Return the `GroupEpoch`
    pub fn psk_epoch(&self) -> GroupEpoch {
        self.psk_epoch
    }
}

/// PSK enum that can contain the different PSK types
#[derive(
    Debug, PartialEq, Eq, Clone, Serialize, Deserialize, TlsSerialize, TlsDeserialize, TlsSize,
)]
#[allow(missing_docs)]
#[repr(u8)]
pub enum Psk {
    #[tls_codec(discriminant = 1)]
    External(ExternalPsk),
    Resumption(ResumptionPsk),
}

/// ResumptionPSKUsage
///
/// ```c
/// // draft-ietf-mls-protocol-16
/// enum {
///   reserved(0),
///   application(1),
///   reinit(2),
///   branch(3),
///   (255)
/// } ResumptionPSKUsage;
/// ```
#[derive(
    Debug,
    PartialEq,
    Eq,
    Clone,
    Copy,
    Hash,
    Serialize,
    Deserialize,
    TlsDeserialize,
    TlsSerialize,
    TlsSize,
)]
#[repr(u8)]
#[allow(missing_docs)]
pub enum ResumptionPskUsage {
    Application = 1,
    Reinit = 2,
    Branch = 3,
}

/// A `PreSharedKeyID` is used to uniquely identify the PSKs that get injected
/// in the key schedule.
///
/// ```c
/// // draft-ietf-mls-protocol-16
/// struct {
///   PSKType psktype;
///   select (PreSharedKeyID.psktype) {
///   case external:
///     opaque psk_id<V>;
///   case resumption:
///     ResumptionPSKUsage usage;
///     opaque psk_group_id<V>;
///     uint64 psk_epoch;
///   opaque psk_nonce<V>;
/// } PreSharedKeyID;
/// ```
#[derive(
    Debug, PartialEq, Eq, Clone, Serialize, Deserialize, TlsDeserialize, TlsSerialize, TlsSize,
)]
pub struct PreSharedKeyId {
    pub(crate) psk: Psk,
    pub(crate) psk_nonce: VLBytes,
}

impl PreSharedKeyId {
    /// Create a new `PreSharedKeyID`
    pub fn new(psk: Psk, psk_nonce: Vec<u8>) -> Self {
        Self {
            psk,
            psk_nonce: psk_nonce.into(),
        }
    }

    /// Return the PSK
    pub fn psk(&self) -> &Psk {
        &self.psk
    }

    /// Return the PSK nonce
    pub fn psk_nonce(&self) -> &[u8] {
        self.psk_nonce.as_slice()
    }
}
