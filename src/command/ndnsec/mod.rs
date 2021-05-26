use super::*;
use std::ffi::OsString;

pub mod dump;
pub mod list;

pub enum NdnSecCommand {
    List,
    Dump(String),
}

impl Command for NdnSecCommand {
    fn to_command(&self) -> Vec<OsString> {
        match self {
            NdnSecCommand::List => ["/usr/bin/ndnsec", "list", "-c"]
                .iter()
                .map(OsString::from)
                .collect(),
            NdnSecCommand::Dump(identity) => ["/usr/bin/ndnsec", "cert-dump", "-p", "-i", identity.as_str()]
                .iter()
                .map(OsString::from)
                .collect(),
        }
    }
}
