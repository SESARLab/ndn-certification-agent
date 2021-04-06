use async_std::{io, process};
use async_trait::async_trait;
use std::ffi::OsString;
use thiserror::Error as ThisError;

/// Command error
#[derive(Debug, Clone, ThisError)]
pub enum Error {
    /// An error occurred while executing a command
    #[error("{0}")]
    OutputError(String),

    /// XML parsing error
    #[error("{0}")]
    XmlParsingError(String),

    #[error("{0}")]
    NomParsingError(String),

    /// Generic IO error
    #[error("{0}")]
    IoError(String),

    /// UTF8 conversion error
    #[error(transparent)]
    FromUtf8Error(#[from] std::string::FromUtf8Error),
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Error::IoError(format!("{}", error))
    }
}

impl From<serde_xml_rs::Error> for Error {
    fn from(error: serde_xml_rs::Error) -> Self {
        Error::XmlParsingError(format!("{}", error))
    }
}

#[async_trait]
pub trait Command {
    fn to_command(&self) -> Vec<OsString>;
    async fn run(&self) -> Result<String, Error> {
        let args = self.to_command();
        let res: process::Output = process::Command::new("/bin/env")
            .args(args)
            .output()
            .await?;
        if res.status.success() {
            Ok(String::from_utf8(res.stdout)?)
        } else {
            let err = String::from_utf8(res.stderr)?;
            Err(Error::OutputError(err))
        }
    }
}

pub mod ndnsec;
pub mod nfdc;
