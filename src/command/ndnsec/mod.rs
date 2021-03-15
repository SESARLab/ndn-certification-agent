use super::*;
use std::ffi::OsString;

pub mod dump;
pub mod list;

pub enum NDNSecCommand {
    List,
    Dump(String),
}

impl Command for NDNSecCommand {
    fn to_command(&self) -> Vec<OsString> {
        match self {
            NDNSecCommand::List => ["ndnsec", "list", "-c"]
                .iter()
                .map(OsString::from)
                .collect(),
            NDNSecCommand::Dump(identity) => ["ndnsec", "cert-dump", "-p", "-i", identity.as_str()]
                .iter()
                .map(OsString::from)
                .collect(),
        }
    }
}
