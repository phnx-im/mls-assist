use super::*;
use openmls::prelude::ProcessedMessage;

impl Group {
    pub fn process_message(&mut self, assisted_message: AssistedMessage) -> ProcessedMessage {
        match assisted_message {
            AssistedMessage::Commit(_assisted_commit) => todo!(),
            AssistedMessage::NonCommit(_) => todo!(),
        }
    }
}
