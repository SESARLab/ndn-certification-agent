use async_std::{io, process};
use async_trait::async_trait;
use std::ffi::OsString;
use thiserror::Error as ThisError;

/// Command error
#[derive(Debug, ThisError)]
pub enum Error {
    /// Unspecified error
    #[error("{0}")]
    Error(String),

    /// An error occurred while executing a command
    #[error("{0}")]
    OutputError(String),

    /// XML parsing error
    #[error(transparent)]
    XMLParsingError(#[from] serde_xml_rs::Error),

		#[error("{0}")]
		NOMParsingError(String),

    /// Generic IO error
    #[error(transparent)]
    IoError(#[from] io::Error),

    /// UTF8 conversion error
    #[error(transparent)]
    FromUtf8Error(#[from] std::string::FromUtf8Error),
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

pub mod nfdc;
pub mod ndnsec;


// #[cfg(test)]
// mod tests {
//     use crate::command::*;
//     #[test]
//     fn test_general_nfd_status() {
//         let m = "General NFD status:
//     version=0.7.1-5-gdbc23a5c
//     startTime=20210209T140051.283000
//     currentTime=20210209T154321.708000
//     uptime=6150 seconds
//     nNameTreeEntries=10
//     nFibEntries=2
//     nPitEntries=2
//     nMeasurementsEntries=0
//     nCsEntries=2
//     nInInterests=228
//     nOutInterests=228
//     nInData=120
//     nOutData=104
//     nInNacks=0
//     nOutNacks=0
//     nSatisfiedInterests=104
//     nUnsatisfiedInterests=122
// other";
//         let (input, _res) = GeneralNFDStatus::parse(m).unwrap();
//         // println!("{:#?}", _res);
//         assert_eq!(input, "other")
//     }
//     #[test]
//     fn test_channels() {
//         let m = "Channels:
// 	dev://br-4e7c0aa85adb
// 	dev://cni0
// 	dev://docker0
// 	dev://enp60s0
// 	dev://vethe0a45f6
// 	dev://virbr0
// 	dev://wlp0s20f3
// 	unix:///run/nfd.sock
// 	ws://0.0.0.0:9696
// 	ws://[::]:9696
// 	udp4://0.0.0.0:6363
// 	udp6://[::]:6363
// 	tcp4://0.0.0.0:6363
// 	tcp6://[::]:6363
// other";
//         let (input, _res) = Channels::parse(m).unwrap();
//         // println!("{:#?}", _res);
//         assert_eq!(input, "other")
//     }
//     #[test]
//     fn test_face() {
//         let m = "faceid=263 remote=fd://64 local=unix:///run/nfd.sock congestion={base-marking-interval=100ms default-threshold=65536B} mtu=8800 counters={in={64i 5d 0n 6967B} out={5i 63d 0n 17272B} interest_size={812min 855max 833.6avg 16.8018std_dev} data_size={39min 121max 58.4444avg 15.5364std_dev} interest_components={5min 9max 5.44445avg 1.26718std_dev} data_components={5min 9max 5.44445avg 1.26718std_dev}} flags={local on-demand point-to-point local-fields congestion-marking}
//             other";
//         let (input, _res) = Face::parse(m).unwrap();
//         // println!("{:#?}", _res);
//         assert_eq!(input, "other");
//         let m = "faceid=254 remote=contentstore:// local=contentstore:// mtu=8800 counters={in={0i 0d 0n 0B} out={0i 0d 0n 0B} interest_size={18446744073709551615min 18446744073709551615max -nanavg 0std_dev} data_size={18446744073709551615min 18446744073709551615max -nanavg 0std_dev} interest_components={18446744073709551615min 18446744073709551615max -nanavg 0std_dev} data_components={18446744073709551615min 18446744073709551615max -nanavg 0std_dev}} flags={
//               local permanent point-to-point}
//               other";
//         let (input, _res) = Face::parse(m).unwrap();
//         // println!("{:#?}", _res);
//         assert_eq!(input, "other");
//     }
//     #[test]
//     fn test_fib_entry() {
//         let m = "/localhost/nfd/rib nexthops={
//   			faceid=263 (cost=0)}
//   			other";
//         let (input, _res) = FibEntry::parse(m).unwrap();
//         // println!("{:?}", _res);
//         assert_eq!(input, "other");
//     }
//     #[test]
//     fn test_fib() {
//         let m = "FIB:
//   /localhost/nfd/rib nexthops={faceid=263 (cost=0)}
//     /localhost/nfd nexthops={faceid=1 (cost=0)}
//     other";
//         let (input, _res) = Fib::parse(m).unwrap();
//         // println!("{:?}", _res);
//         assert_eq!(input, "other");
//     }
//     #[test]
//     fn test_rib_entry() {
//         let m = "/localhost/nfd routes={nexthop=263 origin=app cost=0 flags=child-inherit expires=never}
// 					other";
//         let (input, _res) = RibEntry::parse(m).unwrap();
//         // println!("{:#?}", _res);
//         assert_eq!(input, "other");
//     }
//     #[test]
//     fn test_cs_info() {
//         let m = "CS information:
//   capacity=65536
//   admit=on
//   serve=on
//   nEntries=2
//   nHits=0
//   nMisses=36
//   policyName=lru
//   minSize=0
//   maxSize=48
//   averageSize=43.5
//   stdDevSize=6.96419
// other";
//         let (input, _res) = CsInformation::parse(m).unwrap();
//         // println!("{:#?}", _res);
//         assert_eq!(input, "other");
//     }
//     #[test]
//     fn test_strategy_choices() {
//         let m = "Strategy choices:
// 	prefix=/ strategy=/localhost/nfd/strategy/best-route/%FD%05
// 	prefix=/localhost strategy=/localhost/nfd/strategy/multicast/%FD%03
// 	prefix=/ndn/broadcast strategy=/localhost/nfd/strategy/multicast/%FD%03
// 	prefix=/localhost/nfd strategy=/localhost/nfd/strategy/best-route/%FD%05
// other";
//         let (input, _res) = StrategyChoices::parse(m).unwrap();
//         // println!("{:#?}", _res);
//         assert_eq!(input, "other");
//     }
//     #[async_std::test]
//     #[ignore = "needs the backend running"]
//     async fn test_status_response() {
//         let cmd = NFDStatusCommand;
//         let res = cmd.execute().await.unwrap();
//         let (remaining, parsed_res) = NFDStatusResponse::parse(&res).unwrap();
//         println!("{:#?}", parsed_res);
//         assert!(remaining.is_empty());
//     }
//     #[test]
//     fn test_certificate() {
//         let m = "  /test
//   +->* /test/KEY/%A8C%0C%13%ADd%3B%9B
//        +->* /test/KEY/%A8C%0C%13%ADd%3B%9B/self/%FD%00%00%01s%BF%E4U%3C
// other";
//         let (input, res) = Certificate::parse(m).unwrap();
//         assert!(!res.is_default);
//         assert_eq!(res.identity, "/test");
//         assert_eq!(res.key, "/test/KEY/%A8C%0C%13%ADd%3B%9B");
//         assert_eq!(
//             res.certificate,
//             "/test/KEY/%A8C%0C%13%ADd%3B%9B/self/%FD%00%00%01s%BF%E4U%3C"
//         );
//         assert_eq!(input, "other");
//         let m = "* /test
//                   +->* /test/KEY/%A8C%0C%13%ADd%3B%9B
//                          +->* /test/KEY/%A8C%0C%13%ADd%3B%9B/self/%FD%00%00%01s%BF%E4U%3C
//                          other";
//         let (input, res) = Certificate::parse(m).unwrap();
//         assert!(res.is_default);
//         assert_eq!(res.identity, "/test");
//         assert_eq!(res.key, "/test/KEY/%A8C%0C%13%ADd%3B%9B");
//         assert_eq!(
//             res.certificate,
//             "/test/KEY/%A8C%0C%13%ADd%3B%9B/self/%FD%00%00%01s%BF%E4U%3C"
//         );
//         assert_eq!(input, "other");
//     }
//     #[async_std::test]
//     async fn test_list_response() {
//         let cmd = CertificateListCommand;
//         let res = cmd.execute().await.unwrap();
//         let (remaining, parsed_res) = CertificateListResponse::parse(&res).unwrap();
//         println!("{:#?}", parsed_res);
//         assert!(remaining.is_empty());
//     }

//     #[async_std::test]
//     async fn test_certificate_info() {
//         let certificate = "/test/KEY/%A8C%0C%13%ADd%3B%9B/self/%FD%00%00%01s%BF%E4U%3C".to_string();
//         let cmd = CertificateInfoCommand { certificate };
//         let res = cmd.execute().await.unwrap();
//         let (remaining, parsed_res) = CertificateInfoResponse::parse(&res).unwrap();
//         println!("{:#?}", parsed_res);
//         assert!(remaining.is_empty());
//     }
// }
