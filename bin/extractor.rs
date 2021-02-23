use async_std::prelude::*;
use ndn_certification_agent::command::{self, Command};
use std::time::Duration;

#[async_std::main]
async fn main() {
    let cmd = command::NFDStatusCommand;
    let res: command::NFDStatusResponse = cmd
        .response()
        .timeout(Duration::from_millis(1000))
        .await
        .unwrap()
        .unwrap();
    println!("{:#?}", res);

    let cmd = command::CertificateListCommand;
    let res: command::CertificateListResponse = cmd
        .response()
        .timeout(Duration::from_millis(1000))
        .await
        .unwrap()
        .unwrap();
    println!("{:#?}", res);

    let res = futures::future::join_all(res.certificates.iter().cloned().map(move |c| async {
        let cmd = command::CertificateInfoCommand {
            certificate: c.certificate,
        };
        cmd.response()
            .timeout(Duration::from_millis(1000))
            .await
            .unwrap()
    }))
    .await;

    println!("{:#?}", res)
}
