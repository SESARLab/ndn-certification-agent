use async_std::{
    io,
    process::{Command, Output},
};
use std::ffi::OsString;
use thiserror::Error as ThisError;

/// Client error
#[derive(Debug, ThisError)]
pub enum Error {
    /// Unspecified error
    #[error("{0}")]
    Error(String),
    /// Found zero face
    #[error("{0}")]
    NotFound(String),
    /// Error during FaceUri canonization
    #[error("{0}")]
    CanonizeError(String),
    /// Found multiple faces and allowMulti is false
    #[error("{0}")]
    Ambiguous(String),
    /// No route
    #[error("{0}")]
    Nack(String),
    /// Generic IO error
    #[error(transparent)]
    IoError(#[from] io::Error),
    /// UTF8 conversion error
    #[error(transparent)]
    FromUtf8Error(#[from] std::string::FromUtf8Error),
}

pub struct Request;

impl Request {
    fn to_nfdc_arguments() -> Vec<OsString> {
        ["status", "report"].iter().map(OsString::from).collect()
    }

    pub async fn execute() -> Result<String, Error> {
        let args = Self::to_nfdc_arguments();
        let res: Output = Command::new("/bin/env")
            .arg("nfdc")
            .args(args)
            .output()
            .await?;

        if res.status.success() {
            Ok(String::from_utf8(res.stdout)?)
        } else {
            let err = String::from_utf8(res.stderr)?;
            Err(match res.status.code() {
                Some(1) => Error::Error(err),
                Some(3) => Error::NotFound(err),
                Some(4) => Error::CanonizeError(err),
                Some(5) => Error::Ambiguous(err),
                Some(6) => Error::Nack(err),
                code => unimplemented!("code: {:?} - error: {}", code, err),
            })
        }
    }
}

pub mod response {
    use nom::{
        branch::*, bytes::complete::*, character::complete::*, combinator::*, multi::*,
        sequence::*, IResult,
    };
    use serde::{Deserialize, Serialize};
    use std::str::FromStr;

    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    pub struct Response {
        pub general_nfd_status: GeneralNFDStatus,
        pub channels: Channels,
        pub faces: Faces,
        pub fib: Fib,
        pub rib: Rib,
        pub cs_info: CsInformation,
        pub strategy_choices: StrategyChoices,
    }

    impl Response {
        pub fn parse(input: &str) -> IResult<&str, Self> {
            let (input, general_nfd_status) = GeneralNFDStatus::parse(input)?;
            let (input, channels) = Channels::parse(input)?;
            let (input, faces) = Faces::parse(input)?;
            let (input, fib) = Fib::parse(input)?;
            let (input, rib) = Rib::parse(input)?;
            let (input, cs_info) = CsInformation::parse(input)?;
            let (input, strategy_choices) = StrategyChoices::parse(input)?;
            Ok((
                input,
                Response {
                    general_nfd_status,
                    channels,
                    faces,
                    fib,
                    rib,
                    cs_info,
                    strategy_choices,
                },
            ))
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct GeneralNFDStatus {
        pub version: String,
        pub start_time: String,
        pub current_time: String,
        pub uptime: String,
        pub n_name_tree_entries: u64,
        pub n_fib_entries: u64,
        pub n_pit_entries: u64,
        pub n_measurements_entries: u64,
        pub n_cs_entries: u64,
        pub n_in_interests: u64,
        pub n_out_interests: u64,
        pub n_in_data: u64,
        pub n_out_data: u64,
        pub n_in_nacks: u64,
        pub n_out_nacks: u64,
        pub n_satisfied_interests: u64,
        pub n_unsatisfied_interests: u64,
    }

    impl GeneralNFDStatus {
        fn parse(input: &str) -> IResult<&str, Self> {
            let (input, _) = terminated(tag("General NFD status:"), newline)(input)?;

            let mut string_pair = delimited(
                multispace1,
                separated_pair(
                    take_until("="),
                    tag("="),
                    map(take_until("\n"), String::from),
                ),
                newline,
            );
            let (input, (_, version)) = string_pair(input)?;
            let (input, (_, start_time)) = string_pair(input)?;
            let (input, (_, current_time)) = string_pair(input)?;
            let (input, (_, uptime)) = string_pair(input)?;

            let mut string_uint_pair = delimited(
                multispace1,
                separated_pair(
                    take_until("="),
                    tag("="),
                    map_res(alphanumeric1, u64::from_str),
                ),
                newline,
            );

            let (input, (_, n_name_tree_entries)) = string_uint_pair(input)?;
            let (input, (_, n_fib_entries)) = string_uint_pair(input)?;
            let (input, (_, n_pit_entries)) = string_uint_pair(input)?;
            let (input, (_, n_measurements_entries)) = string_uint_pair(input)?;
            let (input, (_, n_cs_entries)) = string_uint_pair(input)?;
            let (input, (_, n_in_interests)) = string_uint_pair(input)?;
            let (input, (_, n_out_interests)) = string_uint_pair(input)?;
            let (input, (_, n_in_data)) = string_uint_pair(input)?;
            let (input, (_, n_out_data)) = string_uint_pair(input)?;
            let (input, (_, n_in_nacks)) = string_uint_pair(input)?;
            let (input, (_, n_out_nacks)) = string_uint_pair(input)?;
            let (input, (_, n_satisfied_interests)) = string_uint_pair(input)?;
            let (input, (_, n_unsatisfied_interests)) = string_uint_pair(input)?;

            let (input, _) = multispace0(input)?;

            Ok((
                input,
                GeneralNFDStatus {
                    version,
                    start_time,
                    current_time,
                    uptime,
                    n_name_tree_entries,
                    n_fib_entries,
                    n_pit_entries,
                    n_measurements_entries,
                    n_cs_entries,
                    n_in_interests,
                    n_out_interests,
                    n_in_data,
                    n_out_data,
                    n_in_nacks,
                    n_out_nacks,
                    n_satisfied_interests,
                    n_unsatisfied_interests,
                },
            ))
        }
    }

    #[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct Channels(Vec<String>);

    impl Channels {
        fn parse(input: &str) -> IResult<&str, Self> {
            let (input, _) = terminated(tag("Channels:"), newline)(input)?;

            let (input, res) = many1(map(
                delimited(multispace1, take_until("\n"), newline),
                String::from,
            ))(input)?;

            Ok((input, Channels(res)))
        }
    }

    #[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct Counters {
        interest: u64,
        data: u64,
        nack: u64,
        bytes: u64,
    }

    impl Counters {
        fn parse(input: &str) -> IResult<&str, Self> {
            let (input, (interest, data, nack, bytes)) = delimited(
                tag("{"),
                tuple((
                    map_res(delimited(multispace0, digit1, tag("i")), u64::from_str),
                    map_res(delimited(multispace0, digit1, tag("d")), u64::from_str),
                    map_res(delimited(multispace0, digit1, tag("n")), u64::from_str),
                    map_res(delimited(multispace0, digit1, tag("B")), u64::from_str),
                )),
                tag("}"),
            )(input)?;

            Ok((
                input,
                Counters {
                    interest,
                    data,
                    nack,
                    bytes,
                },
            ))
        }
    }

    #[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
    pub struct Statistics {
        min: u64,
        max: u64,
        avg: f64,
        std_dev: f64,
    }

    impl Statistics {
        fn parse(input: &str) -> IResult<&str, Self> {
            let (input, _) = tag("{")(input)?;
            let (input, min) =
                map_res(delimited(multispace0, digit1, tag("min")), u64::from_str)(input)?;
            let (input, max) =
                map_res(delimited(multispace0, digit1, tag("max")), u64::from_str)(input)?;
            let (input, avg) = delimited(
                multispace0,
                map_res(take_until("avg"), |v| match v {
                    "-nan" => Ok(f64::NAN),
                    v => f64::from_str(v),
                }),
                tag("avg"),
            )(input)?;
            let (input, std_dev) = delimited(
                multispace0,
                map_res(take_until("std_dev"), |v| match v {
                    "-nan" => Ok(f64::NAN),
                    v => f64::from_str(v),
                }),
                tag("std_dev"),
            )(input)?;

            let (input, _) = tag("}")(input)?;

            Ok((
                input,
                Statistics {
                    min,
                    max,
                    avg,
                    std_dev,
                },
            ))
        }
    }

    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    pub struct Face {
        face_id: u64,
        remote: String,
        local: String,
        congestion: Option<Vec<String>>,
        mtu: Option<u64>,
        in_counters: Counters,
        out_counters: Counters,
        interest_size: Statistics,
        data_size: Statistics,
        interest_components: Statistics,
        data_components: Statistics,
        flags: Vec<String>,
    }

    impl Face {
        fn parse(input: &str) -> IResult<&str, Self> {
            let mut pair_u64 = preceded(
                multispace0,
                preceded(
                    take_until("="),
                    preceded(tag("="), map_res(take_until(" "), u64::from_str)),
                ),
            );
            let mut pair_string = preceded(
                multispace0,
                preceded(
                    take_until("="),
                    preceded(tag("="), map(take_until(" "), String::from)),
                ),
            );

            let mut p_mtu = opt(preceded(
                multispace0,
                preceded(tag("mtu="), map_res(take_until(" "), u64::from_str)),
            ));
            let mut p_congestion = opt(preceded(
                multispace0,
                preceded(
                    tag("congestion="),
                    delimited(
                        tag("{"),
                        separated_list0(tag(" "), map(is_not(" }"), String::from)),
                        tag("}"),
                    ),
                ),
            ));
            let mut p_flags = preceded(
                multispace0,
                preceded(
                    tag("flags="),
                    delimited(
                        terminated(tag("{"), multispace0),
                        separated_list0(tag(" "), map(is_not(" }"), String::from)),
                        preceded(multispace0, tag("}")),
                    ),
                ),
            );

            let (input, face_id) = pair_u64(input)?;
            let (input, remote) = pair_string(input)?;
            let (input, local) = pair_string(input)?;
            let (input, congestion) = p_congestion(input)?;
            let (input, mtu) = p_mtu(input)?;
            let (
                input,
                (
                    in_counters,
                    out_counters,
                    interest_size,
                    data_size,
                    interest_components,
                    data_components,
                ),
            ) = preceded(
                multispace0,
                preceded(
                    take_until("{"),
                    delimited(
                        tag("{"),
                        tuple((
                            preceded(is_not("{"), Counters::parse),
                            preceded(is_not("{"), Counters::parse),
                            preceded(is_not("{"), Statistics::parse),
                            preceded(is_not("{"), Statistics::parse),
                            preceded(is_not("{"), Statistics::parse),
                            preceded(is_not("{"), Statistics::parse),
                        )),
                        tag("}"),
                    ),
                ),
            )(input)?;
            let (input, flags) = p_flags(input)?;

            let (input, _) = multispace0(input)?;

            Ok((
                input,
                Face {
                    face_id,
                    remote,
                    local,
                    congestion,
                    mtu,
                    in_counters,
                    out_counters,
                    interest_size,
                    data_size,
                    interest_components,
                    data_components,
                    flags,
                },
            ))
        }
    }

    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    pub struct Faces(Vec<Face>);

    impl Faces {
        fn parse(input: &str) -> IResult<&str, Self> {
            let (input, _) = preceded(multispace0, tag("Faces:"))(input)?;
            let (input, faces) = many0(Face::parse)(input)?;
            let (input, _) = multispace0(input)?;
            Ok((input, Faces(faces)))
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct FibEntry {
        prefix: String,
        next_hops: Vec<(u64, String)>,
    }

    impl FibEntry {
        fn parse(input: &str) -> IResult<&str, Self> {
            let (input, prefix) = preceded(multispace0, map(is_not(" "), String::from))(input)?;
            let (input, next_hops) = preceded(
                multispace0,
                preceded(
                    tag("nexthops="),
                    delimited(
                        tag("{"),
                        many0(tuple((
                            preceded(
                                multispace0,
                                preceded(tag("faceid="), map_res(digit1, u64::from_str)),
                            ),
                            preceded(
                                multispace0,
                                delimited(tag("("), map(is_not(")"), String::from), tag(")")),
                            ),
                        ))),
                        tag("}"),
                    ),
                ),
            )(input)?;
            let (input, _) = multispace0(input)?;

            Ok((input, FibEntry { prefix, next_hops }))
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct Fib(Vec<FibEntry>);

    impl Fib {
        fn parse(input: &str) -> IResult<&str, Self> {
            let (input, entries) =
                preceded(multispace0, preceded(tag("FIB:"), many0(FibEntry::parse)))(input)?;

            Ok((input, Fib(entries)))
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct RibEntry {
        prefix: String,
        routes: Vec<(String, String)>,
    }

    impl RibEntry {
        fn parse(input: &str) -> IResult<&str, Self> {
            let (input, prefix) = preceded(multispace0, map(is_not(" "), String::from))(input)?;
            let (input, routes) = preceded(
                multispace0,
                preceded(
                    tag("routes="),
                    delimited(
                        tag("{"),
                        separated_list1(
                            multispace1,
                            separated_pair(
                                map(is_not("="), String::from),
                                tag("="),
                                map(is_not(" }"), String::from),
                            ),
                        ),
                        tag("}"),
                    ),
                ),
            )(input)?;

            let (input, _) = multispace0(input)?;

            Ok((input, RibEntry { prefix, routes }))
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct Rib(Vec<RibEntry>);

    impl Rib {
        fn parse(input: &str) -> IResult<&str, Self> {
            let (input, _) = preceded(multispace0, tag("RIB:"))(input)?;
            let (input, entries) = preceded(multispace0, many0(RibEntry::parse))(input)?;

            Ok((input, Rib(entries)))
        }
    }

    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    pub struct CsInformation {
        capacity: u64,
        admit: bool,
        serve: bool,
        n_entries: u64,
        n_hits: u64,
        n_misses: u64,
        policy_name: String,
        min_size: u64,
        max_size: u64,
        avg_size: f64,
        std_dev_size: f64,
    }

    impl CsInformation {
        fn parse(input: &str) -> IResult<&str, Self> {
            let (input, _) = preceded(multispace0, tag("CS information:"))(input)?;
            let (input, capacity) = map_res(
                preceded(multispace0, preceded(tag("capacity="), digit1)),
                u64::from_str,
            )(input)?;
            let (input, admit) = preceded(
                multispace0,
                preceded(
                    tag("admit="),
                    alt((map(tag("on"), |_| true), map(tag("off"), |_| false))),
                ),
            )(input)?;
            let (input, serve) = preceded(
                multispace0,
                preceded(
                    tag("serve="),
                    alt((map(tag("on"), |_| true), map(tag("off"), |_| false))),
                ),
            )(input)?;
            let (input, n_entries) = map_res(
                preceded(multispace0, preceded(tag("nEntries="), digit1)),
                u64::from_str,
            )(input)?;
            let (input, n_hits) = map_res(
                preceded(multispace0, preceded(tag("nHits="), digit1)),
                u64::from_str,
            )(input)?;
            let (input, n_misses) = map_res(
                preceded(multispace0, preceded(tag("nMisses="), digit1)),
                u64::from_str,
            )(input)?;
            let (input, policy_name) = preceded(
                multispace0,
                preceded(
                    tag("policyName="),
                    map(is_not("\n"), |s: &str| String::from(s.trim())),
                ),
            )(input)?;

            let (input, min_size) = map_res(
                preceded(multispace0, preceded(tag("minSize="), digit1)),
                u64::from_str,
            )(input)?;
            let (input, max_size) = map_res(
                preceded(multispace0, preceded(tag("maxSize="), digit1)),
                u64::from_str,
            )(input)?;
            let (input, avg_size) = preceded(
                multispace0,
                preceded(
                    tag("averageSize="),
                    map_res(is_not("\n"), |s: &str| f64::from_str(s.trim())),
                ),
            )(input)?;
            let (input, std_dev_size) = preceded(
                multispace0,
                preceded(
                    tag("stdDevSize="),
                    map_res(is_not("\n"), |s: &str| f64::from_str(s.trim())),
                ),
            )(input)?;

            let (input, _) = multispace0(input)?;

            Ok((
                input,
                CsInformation {
                    capacity,
                    admit,
                    serve,
                    n_entries,
                    n_hits,
                    n_misses,
                    policy_name,
                    min_size,
                    max_size,
                    avg_size,
                    std_dev_size,
                },
            ))
        }
    }

    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    pub struct StrategyChoices(Vec<(String, String)>);

    impl StrategyChoices {
        fn parse(input: &str) -> IResult<&str, Self> {
            let (input, _) = preceded(multispace0, tag("Strategy choices:"))(input)?;
            let (input, entries) = preceded(
                multispace0,
                separated_list0(
                    multispace1,
                    separated_pair(
                        preceded(
                            tag("prefix="),
                            map(is_not(" "), |s: &str| String::from(s.trim())),
                        ),
                        multispace1,
                        preceded(
                            tag("strategy="),
                            map(is_not("\n"), |s: &str| String::from(s.trim())),
                        ),
                    ),
                ),
            )(input)?;

            let (input, _) = multispace0(input)?;

            Ok((input, StrategyChoices(entries)))
        }
    }

    #[cfg(test)]
    mod tests {

        use crate::client::response::*;
        use crate::client::*;

        #[test]
        fn test_general_nfd_status() {
            let m = "General NFD status:
    version=0.7.1-5-gdbc23a5c
    startTime=20210209T140051.283000
    currentTime=20210209T154321.708000
    uptime=6150 seconds
    nNameTreeEntries=10
    nFibEntries=2
    nPitEntries=2
    nMeasurementsEntries=0
    nCsEntries=2
    nInInterests=228
    nOutInterests=228
    nInData=120
    nOutData=104
    nInNacks=0
    nOutNacks=0
    nSatisfiedInterests=104
    nUnsatisfiedInterests=122
other";

            let (input, _res) = GeneralNFDStatus::parse(m).unwrap();
            // println!("{:#?}", _res);
            assert_eq!(input, "other")
        }

        #[test]
        fn test_channels() {
            let m = "Channels:
	dev://br-4e7c0aa85adb
	dev://cni0
	dev://docker0
	dev://enp60s0
	dev://vethe0a45f6
	dev://virbr0
	dev://wlp0s20f3
	unix:///run/nfd.sock
	ws://0.0.0.0:9696
	ws://[::]:9696
	udp4://0.0.0.0:6363
	udp6://[::]:6363
	tcp4://0.0.0.0:6363
	tcp6://[::]:6363
other";

            let (input, _res) = Channels::parse(m).unwrap();
            // println!("{:#?}", _res);
            assert_eq!(input, "other")
        }

        #[test]
        fn test_face() {
            let m = "faceid=263 remote=fd://64 local=unix:///run/nfd.sock congestion={base-marking-interval=100ms default-threshold=65536B} mtu=8800 counters={in={64i 5d 0n 6967B} out={5i 63d 0n 17272B} interest_size={812min 855max 833.6avg 16.8018std_dev} data_size={39min 121max 58.4444avg 15.5364std_dev} interest_components={5min 9max 5.44445avg 1.26718std_dev} data_components={5min 9max 5.44445avg 1.26718std_dev}} flags={local on-demand point-to-point local-fields congestion-marking}
            other";

            let (input, _res) = Face::parse(m).unwrap();
            // println!("{:#?}", _res);
            assert_eq!(input, "other");

            let m = "faceid=254 remote=contentstore:// local=contentstore:// mtu=8800 counters={in={0i 0d 0n 0B} out={0i 0d 0n 0B} interest_size={18446744073709551615min 18446744073709551615max -nanavg 0std_dev} data_size={18446744073709551615min 18446744073709551615max -nanavg 0std_dev} interest_components={18446744073709551615min 18446744073709551615max -nanavg 0std_dev} data_components={18446744073709551615min 18446744073709551615max -nanavg 0std_dev}} flags={
              local permanent point-to-point}
              other";
            let (input, _res) = Face::parse(m).unwrap();
            // println!("{:#?}", _res);
            assert_eq!(input, "other");
        }

        #[test]
        fn test_fib_entry() {
            let m = "/localhost/nfd/rib nexthops={
  			faceid=263 (cost=0)}
  			other";
            let (input, _res) = FibEntry::parse(m).unwrap();
            // println!("{:?}", _res);
            assert_eq!(input, "other");
        }

        #[test]
        fn test_fib() {
            let m = "FIB:
  /localhost/nfd/rib nexthops={faceid=263 (cost=0)}
    /localhost/nfd nexthops={faceid=1 (cost=0)}
    other";

            let (input, _res) = Fib::parse(m).unwrap();
            // println!("{:?}", _res);
            assert_eq!(input, "other");
        }

        #[test]
        fn test_rib_entry() {
            let m = "/localhost/nfd routes={nexthop=263 origin=app cost=0 flags=child-inherit expires=never}
					other";

            let (input, _res) = RibEntry::parse(m).unwrap();
            // println!("{:#?}", _res);
            assert_eq!(input, "other");
        }

        #[test]
        fn test_cs_info() {
            let m = "CS information:
  capacity=65536
  admit=on
  serve=on
  nEntries=2
  nHits=0
  nMisses=36
  policyName=lru
  minSize=0
  maxSize=48
  averageSize=43.5
  stdDevSize=6.96419
other";

            let (input, _res) = CsInformation::parse(m).unwrap();
            // println!("{:#?}", _res);
            assert_eq!(input, "other");
        }

        #[test]
        fn test_strategy_choices() {
            let m = "Strategy choices:
	prefix=/ strategy=/localhost/nfd/strategy/best-route/%FD%05
	prefix=/localhost strategy=/localhost/nfd/strategy/multicast/%FD%03
	prefix=/ndn/broadcast strategy=/localhost/nfd/strategy/multicast/%FD%03
	prefix=/localhost/nfd strategy=/localhost/nfd/strategy/best-route/%FD%05
other";

            let (input, _res) = StrategyChoices::parse(m).unwrap();
            // println!("{:#?}", _res);
            assert_eq!(input, "other");
        }

        #[async_std::test]
        #[ignore = "needs the backend running"]
        async fn test_response() {
            let res = Request::execute().await.unwrap();
            let (remaining, parsed_res) = Response::parse(&res).unwrap();
            println!("{:#?}", parsed_res);
            println!("{}", remaining);
        }
    }
}
