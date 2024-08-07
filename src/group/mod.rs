use chrono::Duration;
use errors::StorageError;
use openmls::{
    framing::PrivateMessageIn,
    group::MergeCommitError,
    prelude::{
        group_info::{GroupInfo, VerifiableGroupInfo},
        ConfirmationTag, CreationFromExternalError, GroupEpoch, LeafNodeIndex, Member,
        OpenMlsSignaturePublicKey, ProcessedMessage, ProcessedMessageContent, ProposalStore,
        PublicGroup, Sender, SignaturePublicKey, StagedCommit,
    },
    treesync::{LeafNode, RatchetTree, RatchetTreeIn},
};
use openmls_traits::OpenMlsProvider;
use provider::MlsAssistProvider;

use crate::messages::{AssistedGroupInfoIn, AssistedMessageIn, SerializedMlsMessage};

use self::{errors::ProcessAssistedMessageError, past_group_states::PastGroupStates};

pub mod errors;
mod past_group_states;
pub mod process;
pub mod provider;

pub struct Group {
    public_group: PublicGroup,
    group_info: GroupInfo,
    past_group_states: PastGroupStates,
}

impl Group {
    /// Create a new group state.
    pub fn new<Provider: MlsAssistProvider>(
        provider: &Provider,
        verifiable_group_info: VerifiableGroupInfo,
        ratchet_tree: RatchetTreeIn,
    ) -> Result<Self, CreationFromExternalError<StorageError<Provider>>> {
        let (public_group, group_info) = PublicGroup::from_external(
            provider,
            ratchet_tree,
            verifiable_group_info,
            ProposalStore::default(),
        )?;
        let group_id = group_info.group_context().group_id();
        let past_group_states = PastGroupStates::default();
        provider
            .write_group_info(group_id, &group_info)
            .map_err(|e| CreationFromExternalError::WriteToStorageError(e))?;
        provider
            .write_past_group_states(group_id, &past_group_states)
            .map_err(|e| CreationFromExternalError::WriteToStorageError(e))?;
        Ok(Self {
            group_info,
            public_group,
            past_group_states,
        })
    }

    pub fn accept_processed_message<Provider: MlsAssistProvider>(
        &mut self,
        provider: &Provider,
        processed_assisted_message: ProcessedAssistedMessage,
        expiration_time: Duration,
    ) -> Result<(), MergeCommitError<StorageError<Provider>>> {
        let processed_message = match processed_assisted_message {
            ProcessedAssistedMessage::NonCommit(processed_message) => processed_message,
            ProcessedAssistedMessage::Commit(processed_message, group_info) => {
                self.group_info = group_info;
                processed_message
            }
            ProcessedAssistedMessage::PrivateMessage(_) => return Ok(()),
        };
        let added_potential_joiners = match processed_message.into_content() {
            ProcessedMessageContent::StagedCommitMessage(staged_commit) => {
                // We want to add a new state for members that were added to the
                // group via an Add proposal.
                let added_potential_joiners = staged_commit
                    .add_proposals()
                    .map(|add_proposal| {
                        add_proposal
                            .add_proposal()
                            .key_package()
                            .leaf_node()
                            .signature_key()
                            .clone()
                    })
                    .collect();

                self.public_group
                    .merge_commit(provider.storage(), *staged_commit)?;
                added_potential_joiners
            }
            ProcessedMessageContent::ProposalMessage(proposal) => {
                self.public_group.add_proposal(*proposal);
                vec![]
            }
            ProcessedMessageContent::ApplicationMessage(_)
            | ProcessedMessageContent::ExternalJoinProposalMessage(_) => todo!(),
        };
        // Check if any potential joiners were added.
        self.past_group_states.add_state(
            // Note that we're saving the group state after merging the staged
            // commit.
            self.public_group.group_context().epoch(),
            self.public_group.export_ratchet_tree(),
            &added_potential_joiners,
        );
        // Check if any past group state has expired.
        self.past_group_states
            .remove_expired_states(expiration_time);
        let group_id = self.group_info.group_context().group_id();
        provider
            .write_group_info(group_id, self.group_info())
            .map_err(|e| MergeCommitError::StorageError(e))?;
        provider
            .write_past_group_states(group_id, &self.past_group_states)
            .map_err(|e| MergeCommitError::StorageError(e))?;
        Ok(())
    }

    pub fn group_info(&self) -> &GroupInfo {
        &self.group_info
    }

    pub fn export_ratchet_tree(&self) -> RatchetTree {
        self.public_group.export_ratchet_tree()
    }

    pub fn epoch(&self) -> GroupEpoch {
        self.public_group.group_context().epoch()
    }

    /// Get the nodes of the past group state with the given epoch for the given
    /// joiner. Returns `None` if there is no past group state for that epoch
    /// and the given joiner.
    pub fn past_group_state(
        &mut self,
        epoch: &GroupEpoch,
        joiner: &SignaturePublicKey,
    ) -> Option<&RatchetTree> {
        self.past_group_states.get_for_joiner(epoch, joiner)
    }

    pub fn leaf(&self, leaf_index: LeafNodeIndex) -> Option<&LeafNode> {
        self.public_group.leaf(leaf_index)
    }

    pub fn members(&self) -> impl Iterator<Item = Member> + '_ {
        self.public_group.members()
    }
}

pub struct ProcessedAssistedMessagePlus {
    pub processed_assisted_message: ProcessedAssistedMessage,
    pub serialized_mls_message: SerializedMlsMessage,
}

pub enum ProcessedAssistedMessage {
    PrivateMessage(PrivateMessageIn),
    NonCommit(ProcessedMessage),
    Commit(ProcessedMessage, GroupInfo),
}

impl ProcessedAssistedMessage {
    pub fn sender(&self) -> Option<&Sender> {
        match self {
            ProcessedAssistedMessage::NonCommit(pm) | ProcessedAssistedMessage::Commit(pm, _) => {
                Some(pm.sender())
            }
            ProcessedAssistedMessage::PrivateMessage(_) => None,
        }
    }
}
