use async_std::prelude::*;
use std::time::Duration;
use ndn_certification_agent::{client };

#[async_std::main]
async fn main() {
	let res = client::Request::execute()
  	.timeout(Duration::from_millis(1000))
  	.await
  	.unwrap();
	println!("{:?}", res);
}
