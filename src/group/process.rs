use openmls::prelude::{MlsCredentialType, OpenMlsCryptoProvider, ProtocolMessage, Verifiable};

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
                    let assisted_sender = match sender {
                        Sender::Member(leaf_index) => AssistedSender::Member(leaf_index),
                        Sender::NewMemberCommit => {
                            // For now, the only way we can get hold of the signature key (before merging the commit) is to assume that it's an InfraCredential.
                            let signature_key =
                                match processed_message.credential().mls_credential_type() {
                                    MlsCredentialType::Infra(infra_credential) => {
                                        infra_credential.verifying_key().clone()
                                    }
                                    MlsCredentialType::Basic(_) | MlsCredentialType::X509(_) => {
                                        // TODO: For now, this only supports InfraCredentials.
                                        return Err(ProcessAssistedMessageError::UnknownSender);
                                    }
                                };
                            AssistedSender::External(signature_key)
                        }
                        Sender::External(_) | Sender::NewMemberProposal => {
                            return Err(ProcessAssistedMessageError::LibraryError(
                                LibraryError::LibraryError, // Invalid sender after validation.
                            ));
                        }
                    };
                    let group_info: GroupInfo = self.validate_group_info(
                        assisted_sender,
                        staged_commit,
                        confirmation_tag,
                        assisted_group_info,
                    )?;
                    // This is really only relevant for the "Full" group info case above.
                    if group_info.group_context() != staged_commit.group_context() {
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

enum AssistedSender {
    Member(LeafNodeIndex),
    External(SignaturePublicKey),
}

// Helper functions
impl Group {
    fn validate_group_info(
        &self,
        sender: AssistedSender,
        staged_commit: &StagedCommit,
        confirmation_tag: ConfirmationTag,
        assisted_group_info: AssistedGroupInfoIn,
    ) -> Result<GroupInfo, ProcessAssistedMessageError> {
        let signature_scheme = self.group_info().group_context().ciphersuite().into();
        let (sender_index, sender_pk) = match sender {
            AssistedSender::Member(index) => {
                let sender_pk = self
                    .public_group
                    .members()
                    .find_map(|m| {
                        if m.index == index {
                            Some(m.signature_key)
                        } else {
                            None
                        }
                    })
                    .map(|pk_bytes| {
                        OpenMlsSignaturePublicKey::from_signature_key(
                            pk_bytes.into(),
                            signature_scheme,
                        )
                    })
                    .ok_or(ProcessAssistedMessageError::UnknownSender)?;
                (index, sender_pk)
            }
            AssistedSender::External(signature_public_key) => {
                let index = self
                    .public_group
                    .ext_commit_sender_index(staged_commit)
                    .map_err(LibraryError::OpenMlsLibraryError)?;
                let openmls_signature_key = OpenMlsSignaturePublicKey::from_signature_key(
                    signature_public_key,
                    signature_scheme,
                );
                (index, openmls_signature_key)
            }
        };
        let verifiable_group_info = assisted_group_info
            .try_into_verifiable_group_info(
                sender_index,
                staged_commit.group_context().clone(),
                confirmation_tag,
            )
            .map_err(|_| ProcessAssistedMessageError::InvalidGroupInfoMessage)?;

        verifiable_group_info
            .verify(self.backend().crypto(), &sender_pk)
            .map_err(|_| ProcessAssistedMessageError::InvalidGroupInfoSignature)
    }
}
