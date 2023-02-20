use std::collections::HashSet;

use openmls::{prelude::KeyPackageRef, treesync::Node};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub(super) struct PastGroupState {
    potential_joiners: HashSet<KeyPackageRef>,
    nodes: Vec<Option<Node>>,
}

impl From<Vec<Option<Node>>> for PastGroupState {
    fn from(nodes: Vec<Option<Node>>) -> Self {
        Self {
            potential_joiners: HashSet::new(),
            nodes,
        }
    }
}

impl PastGroupState {
    pub(super) fn new(nodes: Vec<Option<Node>>, potential_joiners: Vec<KeyPackageRef>) -> Self {
        let potential_joiners = potential_joiners.into_iter().collect();
        Self {
            potential_joiners,
            nodes,
        }
    }

    pub(super) fn remove_potential_joiners(&mut self, joiners: &[KeyPackageRef]) {
        for joiner in joiners {
            self.potential_joiners.remove(joiner);
        }
    }
}
