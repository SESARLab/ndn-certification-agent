use std::time::Duration;
use thiserror::Error as ThisError;

use async_std::{
    io,
    process::{Command, Output},
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NDNRequest {
    name: String,
    timeout: Option<Duration>,
    allow_prefix: bool,
}

#[derive(Debug, ThisError)]
pub enum Error {
    #[error("{0}")]
    Error(String),
    #[error("Timeout reached")]
    Timeout,
    #[error("{0}")]
    Nack(String),
    #[error("Process killed")]
    ProcessKilled,
    #[error(transparent)]
    IoError(#[from] io::Error),
}

impl NDNRequest {
    pub fn new<S: ToString>(name: S) -> Self {
        Self {
            name: name.to_string(),
            timeout: None,
            allow_prefix: false,
        }
    }

    pub fn set_can_be_prefix(mut self, value: bool) -> Self {
        self.allow_prefix = value;
        self
    }

    pub fn set_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }
}

pub async fn request(req: &NDNRequest) -> Result<Vec<u8>, Error> {
    let mut args = ["ndnpeek", "--payload"]
        .iter()
        .cloned()
        .map(String::from)
        .collect::<Vec<_>>();

    if let Some(timeout) = req.timeout {
        args.push("--timeout".to_string());
        args.push(timeout.as_millis().to_string());
    }

    if req.allow_prefix {
        args.push("--prefix".to_string());
    }

    args.push(req.name.clone());

    println!("{:?}", args);

    let res: Output = Command::new("/bin/env")
        .args(args)
        //.kill_on_drop(true)
        .output()
        .await?;

    match (res.status.success(), res.status.code()) {
        (true, _) => Ok(res.stdout),
        (false, Some(1)) | (false, Some(2)) => {
            Err(Error::Error(String::from_utf8(res.stderr).unwrap()))
        }
        (false, Some(3)) => Err(Error::Timeout),
        (false, Some(4)) => Err(Error::Nack(String::from_utf8(res.stdout).unwrap())),
        (false, None) => Err(Error::ProcessKilled),
        (false, _) => panic!("Should never happen"),
    }
}
