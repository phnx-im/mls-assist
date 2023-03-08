use chrono::Duration;
use openmls::{
    prelude::{
        group_info::{GroupInfo, VerifiableGroupInfo},
        ConfirmationTag, CreationFromExternalError, GroupEpoch, LeafNodeIndex, LibraryError,
        Member, OpenMlsSignaturePublicKey, ProcessedMessage, ProcessedMessageContent,
        ProposalStore, PublicGroup, Sender, SignaturePublicKey, StagedCommit,
    },
    treesync::{LeafNode, Node},
};
use openmls_rust_crypto::OpenMlsRustCrypto;
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
        expiration_time: Duration,
    ) {
        let processed_message = match processed_assisted_message {
            ProcessedAssistedMessage::NonCommit(processed_message) => processed_message,
            ProcessedAssistedMessage::Commit(processed_message, group_info) => {
                self.group_info = group_info;
                processed_message
            }
        };
        let added_potential_joiners =
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

                added_potential_joiners
            } else {
                vec![]
            };
        self.public_group.finalize_processing(processed_message);
        // Check if any potential joiners were added.
        self.past_group_states.add_state(
            // Note that we're saving the group state after merging the staged
            // commit.
            self.public_group.group_context().epoch(),
            self.public_group.export_nodes(),
            &added_potential_joiners,
        );
        // Check if any past group state has expired.
        self.past_group_states
            .remove_expired_states(expiration_time)
    }

    pub fn group_info(&self) -> &GroupInfo {
        &self.group_info
    }

    pub fn export_ratchet_tree(&self) -> Vec<Option<Node>> {
        self.public_group.export_nodes()
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
    ) -> Option<&[Option<Node>]> {
        self.past_group_states.get_for_joiner(epoch, joiner)
    }

    pub fn leaf(&self, leaf_index: LeafNodeIndex) -> Option<&LeafNode> {
        self.public_group.leaf(leaf_index)
    }

    pub fn members(&self) -> impl Iterator<Item = Member> + '_ {
        self.public_group.members()
    }
}

pub enum ProcessedAssistedMessage {
    NonCommit(ProcessedMessage),
    Commit(ProcessedMessage, GroupInfo),
}

impl ProcessedAssistedMessage {
    pub fn sender(&self) -> &Sender {
        match self {
            ProcessedAssistedMessage::NonCommit(pm) | ProcessedAssistedMessage::Commit(pm, _) => {
                pm.sender()
            }
        }
    }
}
