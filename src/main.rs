use async_std::prelude::*;
use std::env::args;
use std::time::Duration;

mod client;
mod error;
mod metrics;
mod protos;
mod rules;

#[async_std::main]
async fn main() {
    let name = args().skip(1).next().unwrap();
    println!("Name: {}", name);
    let req = client::NDNRequest::new(name).set_can_be_prefix(true);
    let res = client::request(&req)
        .timeout(Duration::from_millis(1000))
        .await
        .unwrap();

    match res {
        Ok(res) => match String::from_utf8(res.clone()) {
            Ok(s) => println!("{}", s),
            _ => println!("{:?}", res),
        },
        Err(err) => eprintln!("{:?}", err),
    }
}
