use openmls::{
    prelude::{
        group_info::{GroupInfo, VerifiableGroupInfo},
        ConfirmationTag, CreationFromExternalError, GroupEpoch, LeafNodeIndex, LibraryError,
        OpenMlsSignaturePublicKey, ProcessedMessage, ProcessedMessageContent, ProposalStore,
        PublicGroup, Sender, SignaturePublicKey, StagedCommit, Verifiable,
    },
    treesync::{LeafNode, Node},
};
use openmls_rust_crypto::{OpenMlsCryptoProvider, OpenMlsRustCrypto};
use serde::{Deserialize, Serialize};

use crate::messages::{AssistedCommit, AssistedGroupInfo, AssistedMessage};

use self::{errors::ProcessAssistedMessageError, past_group_states::PastGroupStates};

pub mod errors;
mod past_group_states;
pub mod process;

#[derive(Serialize, Deserialize)]
pub struct Group {
    public_group: PublicGroup,
    group_info: GroupInfo,
    past_group_states: PastGroupStates,
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
            past_group_states: PastGroupStates::default(),
        })
    }

    fn backend(&self) -> &OpenMlsRustCrypto {
        &self.backend
    }

    pub fn accept_processed_message(
        &mut self,
        processed_assisted_message: ProcessedAssistedMessage,
    ) {
        let processed_message = match processed_assisted_message {
            ProcessedAssistedMessage::NonCommit(processed_message) => processed_message,
            ProcessedAssistedMessage::Commit(processed_message, group_info) => {
                self.group_info = group_info;
                processed_message
            }
        };
        let (added_potential_joiners, removed_potential_joiners) =
            if let ProcessedMessageContent::StagedCommitMessage(staged_commit) =
                processed_message.content()
            {
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

                // We want to remove past group states if the corresponding
                // potential joiners are removed from the group ...
                let removed_indices: Vec<LeafNodeIndex> = staged_commit
                    .remove_proposals()
                    .map(|remove| remove.remove_proposal().removed())
                    .collect();

                let mut removed_potential_joiners: Vec<SignaturePublicKey> = self
                    .public_group
                    .members()
                    .filter_map(|member| {
                        if removed_indices.contains(&member.index) {
                            Some(member.signature_key.into())
                        } else {
                            None
                        }
                    })
                    .collect();

                // ... or if they perform an update (showing that they already have the state they need).
                if let Sender::Member(leaf_index) = processed_message.sender() {
                    if let Some(sender_leaf_node) = self.public_group.leaf(*leaf_index) {
                        removed_potential_joiners.push(sender_leaf_node.signature_key().clone());
                    }
                }

                (added_potential_joiners, removed_potential_joiners)
            } else {
                (vec![], vec![])
            };
        self.public_group.finalize_processing(processed_message);
        // Check if any potential joiners were removed ...
        self.past_group_states
            .remove_potential_joiners(&removed_potential_joiners);
        // ... or added.
        self.past_group_states.add_state(
            // Note that we're saving the group state after merging the staged
            // commit.
            self.public_group.group_context().epoch(),
            self.public_group.export_nodes(),
            added_potential_joiners,
        );
    }

    pub fn group_info(&self) -> &GroupInfo {
        &self.group_info
    }

    pub fn past_group_state(&mut self, epoch: &GroupEpoch) -> Option<&[Option<Node>]> {
        self.past_group_states.get(epoch)
    }
}

pub enum ProcessedAssistedMessage {
    NonCommit(ProcessedMessage),
    Commit(ProcessedMessage, GroupInfo),
}
