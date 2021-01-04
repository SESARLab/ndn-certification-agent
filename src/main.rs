use std::env::args;

mod client;
mod rules;
mod metrics;
mod protos;

#[async_std::main]
async fn main() {
    let name = args().skip(1).next().unwrap();
    println!("Name: {}", name);
    let res = client::request(&name, None).await.unwrap();

    if res.status.success() {
        if let Ok(s) = String::from_utf8(res.stdout.clone()) {
            println!("{}", s)
        } else {
            println!("{:?}", res.stdout)
        }
    } else {
        eprintln!("{}", String::from_utf8(res.stderr).unwrap())
    }
}
