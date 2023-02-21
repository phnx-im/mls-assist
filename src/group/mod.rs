use openmls::{
    prelude::Verifiable,
    prelude::{
        group_info::{GroupInfo, VerifiableGroupInfo},
        CreationFromExternalError, ProposalStore, PublicGroup,
    },
    prelude::{
        ConfirmationTag, LibraryError, OpenMlsCryptoProvider, OpenMlsSignaturePublicKey,
        ProcessedMessage, ProcessedMessageContent, Sender, StagedCommit,
    },
    treesync::{LeafNode, Node},
};
use openmls_rust_crypto::OpenMlsRustCrypto;
use serde::{Deserialize, Serialize};

use crate::messages::{AssistedCommit, AssistedGroupInfo, AssistedMessage};

use self::errors::ProcessAssistedMessageError;

pub mod errors;

#[derive(Serialize, Deserialize)]
pub struct Group {
    public_group: PublicGroup,
    group_info: GroupInfo,
    #[serde(skip)]
    backend: OpenMlsRustCrypto,
}

impl Group {
    /// Create a new group state with the group consisting of the creator's
    /// leaf.
    pub fn new(
        verifiable_group_info: VerifiableGroupInfo,
        leaf_node: LeafNode,
    ) -> Result<Self, CreationFromExternalError> {
        let backend = OpenMlsRustCrypto::default();
        let nodes = vec![Some(Node::LeafNode(leaf_node.into()))];
        let (public_group, group_info) = PublicGroup::from_external(
            &backend,
            nodes,
            verifiable_group_info,
            ProposalStore::default(),
        )?;
        Ok(Self {
            group_info,
            public_group,
            backend,
        })
    }

    fn backend(&self) -> &OpenMlsRustCrypto {
        &self.backend
    }

    /// Returns a [`ProcessedMessage`] for inspection.
    pub fn process(
        self,
        assisted_message: AssistedMessage,
    ) -> Result<ProcessedAssistedMessage, ProcessAssistedMessageError> {
        match assisted_message {
            AssistedMessage::NonCommit(public_message) => {
                let processed_message = self
                    .public_group
                    .process_message(self.backend(), public_message)?;
                Ok(ProcessedAssistedMessage::NonCommit(processed_message))
            }
            AssistedMessage::Commit(AssistedCommit {
                commit,
                assisted_group_info,
            }) => {
                // First process the message, then verify that the group info
                // checks out.
                let processed_message = self
                    .public_group
                    .process_message(self.backend(), commit.clone())?;
                let sender = processed_message.sender().clone();
                let confirmation_tag = commit
                    .confirmation_tag()
                    .ok_or(LibraryError::custom(
                        "No confirmation tag in commit after validation.",
                    ))?
                    .clone();
                if let ProcessedMessageContent::StagedCommitMessage(staged_commit) =
                    processed_message.content()
                {
                    let group_info: GroupInfo = self.validate_group_info(
                        sender,
                        staged_commit,
                        confirmation_tag,
                        assisted_group_info,
                    )?;
                    // This is really only relevant for the "Full" group info case above.
                    if group_info.group_context() != staged_commit.staged_context() {
                        return Err(ProcessAssistedMessageError::InconsistentGroupContext);
                    }
                    Ok(ProcessedAssistedMessage::Commit(
                        processed_message,
                        group_info,
                    ))
                } else {
                    Err(ProcessAssistedMessageError::LibraryError(
                        LibraryError::custom("Mismatching message type."),
                    ))
                }
            }
        }
    }

    pub fn accept_message(&mut self, processed_assisted_message: ProcessedAssistedMessage) {
        let processed_message = match processed_assisted_message {
            ProcessedAssistedMessage::NonCommit(processed_message) => processed_message,
            ProcessedAssistedMessage::Commit(processed_message, group_info) => {
                self.group_info = group_info;
                processed_message
            }
        };
        self.public_group.finalize_processing(processed_message)
    }

    pub fn group_info(&self) -> &GroupInfo {
        &self.group_info
    }

    fn validate_group_info(
        &self,
        sender: Sender,
        staged_commit: &StagedCommit,
        confirmation_tag: ConfirmationTag,
        assisted_group_info: AssistedGroupInfo,
    ) -> Result<GroupInfo, ProcessAssistedMessageError> {
        let sender_index = match sender {
            Sender::Member(leaf_index) => leaf_index,
            Sender::NewMemberCommit => self.public_group.free_leaf_index_after_remove(
                staged_commit.inline_proposals().map(|p| p.proposal()),
            )?,
            Sender::External(_) | Sender::NewMemberProposal => {
                return Err(ProcessAssistedMessageError::LibraryError(
                    LibraryError::custom("Invalid sender after validation."),
                ))
            }
        };
        let verifiable_group_info = assisted_group_info.into_verifiable_group_info(
            sender_index,
            staged_commit.staged_context().clone(),
            confirmation_tag,
        );

        let sender_pk = self
            .public_group
            .members()
            .find_map(|m| {
                if m.index == sender_index {
                    Some(m.signature_key)
                } else {
                    None
                }
            })
            .map(|pk_bytes| {
                OpenMlsSignaturePublicKey::from_signature_key(
                    pk_bytes.into(),
                    verifiable_group_info.ciphersuite().into(),
                )
            })
            .ok_or(ProcessAssistedMessageError::UnknownSender)?;
        verifiable_group_info
            .verify(self.backend().crypto(), &sender_pk)
            .map_err(|_| ProcessAssistedMessageError::InvalidGroupInfoSignature)
    }
}

pub enum ProcessedAssistedMessage {
    NonCommit(ProcessedMessage),
    Commit(ProcessedMessage, GroupInfo),
}
