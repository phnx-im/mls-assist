use openmls::prelude::{OpenMlsCryptoProvider, ProposalOrRefType, ProtocolMessage, Verifiable};

use super::{errors::LibraryError, *};

impl Group {
    /// Returns a [`ProcessedMessage`] for inspection.
    pub fn process_assisted_message(
        &self,
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
                let processed_message = self.public_group.process_message(
                    self.backend(),
                    ProtocolMessage::PublicMessage(commit.clone()),
                )?;
                let sender = processed_message.sender().clone();
                let confirmation_tag = commit
                    .confirmation_tag()
                    .ok_or(LibraryError::LibraryError)?
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
                        LibraryError::LibraryError, // Mismatching message type
                    ))
                }
            }
        }
    }
}

// Helper functions
impl Group {
    fn validate_group_info(
        &self,
        sender: Sender,
        staged_commit: &StagedCommit,
        confirmation_tag: ConfirmationTag,
        assisted_group_info: AssistedGroupInfoIn,
    ) -> Result<GroupInfo, ProcessAssistedMessageError> {
        let sender_index = match sender {
            Sender::Member(leaf_index) => leaf_index,
            Sender::NewMemberCommit => self
                .public_group
                .free_leaf_index_after_remove(staged_commit.queued_proposals().filter_map(|p| {
                    if matches!(p.proposal_or_ref_type(), ProposalOrRefType::Proposal) {
                        Some(Some(p.proposal()))
                    } else {
                        None
                    }
                }))
                .map_err(LibraryError::OpenMlsLibraryError)?,
            Sender::External(_) | Sender::NewMemberProposal => {
                return Err(ProcessAssistedMessageError::LibraryError(
                    LibraryError::LibraryError, // Invalid sender after validation.
                ));
            }
        };
        let verifiable_group_info = assisted_group_info
            .try_into_verifiable_group_info(
                sender_index,
                staged_commit.staged_context().clone(),
                confirmation_tag,
            )
            .map_err(|_| ProcessAssistedMessageError::InvalidGroupInfoMessage)?;

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
