use std::collections::{HashMap, HashSet};

use openmls::{
    prelude::{GroupEpoch, SignaturePublicKey},
    treesync::Node,
};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Default)]
pub(super) struct PastGroupStates {
    potential_joiners: HashMap<SignaturePublicKey, GroupEpoch>,
    past_group_states: HashMap<GroupEpoch, Vec<Option<Node>>>,
}

impl PastGroupStates {
    pub(super) fn add_state(
        &mut self,
        epoch: GroupEpoch,
        nodes: Vec<Option<Node>>,
        potential_joiners: Vec<SignaturePublicKey>,
    ) {
        if potential_joiners.is_empty() {
            return;
        }
        for joiner in potential_joiners {
            self.potential_joiners.insert(joiner, epoch);
        }
        self.past_group_states.insert(epoch, nodes);
    }

    pub(super) fn remove_potential_joiners(&mut self, joiners: &[SignaturePublicKey]) {
        let mut affected_epochs = HashSet::new();
        joiners.iter().for_each(|joiner| {
            let epoch_option = self.potential_joiners.remove(joiner);
            if let Some(epoch) = epoch_option {
                affected_epochs.insert(epoch);
            }
        });
        // TODO: Access performance can probably be optimized here, but it's going to
        // be a database at some point anyway.
        affected_epochs.into_iter().for_each(|epoch| {
            if !self
                .potential_joiners
                .values()
                .any(|&joiner_epoch| joiner_epoch == epoch)
            {
                self.past_group_states.remove(&epoch);
            }
        });
    }
}
