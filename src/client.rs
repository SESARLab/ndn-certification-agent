use std::error::Error;
use std::process::{Command, Output};
use std::time::Duration;

pub async fn request(name: &str, timeout: Option<Duration>) -> Result<Output, Box<dyn Error>> {
    let mut args = ["ndnpeek", "--payload", "--prefix"]
        .iter()
        .cloned()
        .map(String::from)
        .collect::<Vec<_>>();

    if let Some(timeout) = timeout {
        let timeout_str = timeout.as_millis().to_string();
        args.push(timeout_str)
    }

    args.push(name.to_string());

    Command::new("/bin/env")
        .args(args)
        .output()
        .map_err(Into::into)
}
