use async_std::{io, process};
use async_trait::async_trait;
use chrono::prelude::*;
use nom::{
    branch::*, bytes::complete::*, character::complete::*, combinator::*, multi::*, sequence::*,
    IResult,
};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, ffi::OsString, str::FromStr};
use thiserror::Error as ThisError;
/// Command error
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
    /// Error during response parsing
    #[error("{0}")]
    ParsingError(String),
    /// Generic IO error
    #[error(transparent)]
    IoError(#[from] io::Error),
    /// UTF8 conversion error
    #[error(transparent)]
    FromUtf8Error(#[from] std::string::FromUtf8Error),
}
pub trait Response: Sized {
    fn parse(input: &str) -> IResult<&str, Self>;
}
#[async_trait(?Send)]
pub trait Command {
    type Res: Response + Send;
    fn to_command(&self) -> Vec<OsString>;
    async fn execute(&self) -> Result<String, Error> {
        let args = self.to_command();
        let res: process::Output = process::Command::new("/bin/env")
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
    async fn response(&self) -> Result<Self::Res, Error> {
        let command_output = self.execute().await?;
        let (_input, res) =
            Self::Res::parse(&command_output).map_err(|e| Error::ParsingError(format!("{}", e)))?;
        debug_assert!(_input.is_empty());
        Ok(res)
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NFDStatusCommand;
impl Command for NFDStatusCommand {
    type Res = NFDStatusResponse;
    fn to_command(&self) -> Vec<OsString> {
        ["nfdc", "status", "report"]
            .iter()
            .map(OsString::from)
            .collect()
    }
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NFDStatusResponse {
    pub general_nfd_status: GeneralNFDStatus,
    pub channels: Channels,
    pub faces: Faces,
    pub fib: Fib,
    pub rib: Rib,
    pub cs_info: CsInformation,
    pub strategy_choices: StrategyChoices,
}
impl Response for NFDStatusResponse {
    fn parse(input: &str) -> IResult<&str, Self> {
        let (input, general_nfd_status) = GeneralNFDStatus::parse(input)?;
        let (input, channels) = Channels::parse(input)?;
        let (input, faces) = Faces::parse(input)?;
        let (input, fib) = Fib::parse(input)?;
        let (input, rib) = Rib::parse(input)?;
        let (input, cs_info) = CsInformation::parse(input)?;
        let (input, strategy_choices) = StrategyChoices::parse(input)?;
        Ok((
            input,
            NFDStatusResponse {
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
    pub interest: u64,
    pub data: u64,
    pub nack: u64,
    pub bytes: u64,
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
    pub min: u64,
    pub max: u64,
    pub avg: f64,
    pub std_dev: f64,
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
    pub face_id: u64,
    pub remote: String,
    pub local: String,
    pub congestion: Option<Vec<String>>,
    pub mtu: Option<u64>,
    pub in_counters: Counters,
    pub out_counters: Counters,
    pub interest_size: Statistics,
    pub data_size: Statistics,
    pub interest_components: Statistics,
    pub data_components: Statistics,
    pub flags: Vec<String>,
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
    pub prefix: String,
    pub next_hops: Vec<(u64, String)>,
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
    pub prefix: String,
    pub routes: Vec<(String, String)>,
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
    pub capacity: u64,
    pub admit: bool,
    pub serve: bool,
    pub n_entries: u64,
    pub n_hits: u64,
    pub n_misses: u64,
    pub policy_name: String,
    pub min_size: u64,
    pub max_size: u64,
    pub avg_size: f64,
    pub std_dev_size: f64,
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertificateListCommand;
impl Command for CertificateListCommand {
    type Res = CertificateListResponse;
    fn to_command(&self) -> Vec<OsString> {
        ["ndnsec", "list", "-c"]
            .iter()
            .map(OsString::from)
            .collect()
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertificateListResponse {
    pub certificates: Vec<Certificate>,
}
impl Response for CertificateListResponse {
    fn parse(input: &str) -> IResult<&str, Self> {
        let (input, certificates) = preceded(multispace0, many0(Certificate::parse))(input)?;
        Ok((input, CertificateListResponse { certificates }))
    }
}
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Certificate {
    pub is_default: bool,
    pub identity: String,
    pub key: String,
    pub certificate: String,
}
impl Certificate {
    fn parse(input: &str) -> IResult<&str, Self> {
        let (input, opt_is_default) =
            delimited(multispace0, opt(tag("*")), take_until("/"))(input)?;
        let (input, identity) = preceded(multispace0, map(take_until("\n"), String::from))(input)?;
        let (input, key) = preceded(
            delimited(multispace0, tag("+->*"), multispace0),
            map(is_not("\n"), String::from),
        )(input)?;
        let (input, certificate) = preceded(
            delimited(multispace0, tag("+->*"), multispace0),
            map(is_not("\n"), String::from),
        )(input)?;
        let (input, _) = multispace0(input)?;
        Ok((
            input,
            Certificate {
                is_default: opt_is_default.is_some(),
                identity,
                key,
                certificate,
            },
        ))
    }
}
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct CertificateInfoCommand {
    pub certificate: String,
}
impl Command for CertificateInfoCommand {
    type Res = CertificateInfoResponse;
    fn to_command(&self) -> Vec<OsString> {
        ["ndnsec-cert-dump", "-p", self.certificate.as_str()]
            .iter()
            .map(OsString::from)
            .collect()
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertificateInfoResponse {
    pub certificate_name: String,
    pub validity_not_before: DateTime<Utc>,
    pub validity_not_after: DateTime<Utc>,
    pub public_key_bits: Vec<u8>,
    pub signature_information: HashMap<String, String>,
}
impl Response for CertificateInfoResponse {
    fn parse(input: &str) -> IResult<&str, Self> {
        let (input, _) = preceded(multispace0, tag("Certificate name:"))(input)?;
        let (input, certificate_name) =
            preceded(multispace0, map(take_until("\n"), String::from))(input)?;
        let (input, _) = preceded(multispace0, tag("Validity:"))(input)?;
        let (input, _) = preceded(multispace0, tag("NotBefore: "))(input)?;
        let (input, validity_not_before) = preceded(
            multispace0,
            map_res(
                tuple((
                    map_res(take(4 as u64), i32::from_str),
                    map_res(take(2 as u64), u32::from_str),
                    map_res(take(2 as u64), u32::from_str),
                    tag("T"),
                    map_res(take(2 as u64), u32::from_str),
                    map_res(take(2 as u64), u32::from_str),
                    map_res(take(2 as u64), u32::from_str),
                )),
                |(year, month, day, _, hour, minute, second)| {
                    Utc.ymd_opt(year, month, day)
                        .and_hms_opt(hour, minute, second)
                        .single()
                        .ok_or_else(|| Error::ParsingError(String::from("Invalid ISO 8601")))
                },
            ),
        )(input)?;
        let (input, _) = preceded(multispace0, tag("NotAfter: "))(input)?;
        let (input, validity_not_after) = preceded(
            multispace0,
            map_res(
                tuple((
                    map_res(take(4_u64), i32::from_str),
                    map_res(take(2_u64), u32::from_str),
                    map_res(take(2_u64), u32::from_str),
                    tag("T"),
                    map_res(take(2_u64), u32::from_str),
                    map_res(take(2_u64), u32::from_str),
                    map_res(take(2_u64), u32::from_str),
                )),
                |(year, month, day, _, hour, minute, second)| {
                    Utc.ymd_opt(year, month, day)
                        .and_hms_opt(hour, minute, second)
                        .single()
                        .ok_or_else(|| Error::ParsingError(String::from("Invalid ISO 8601")))
                },
            ),
        )(input)?;
        let (input, _) = preceded(multispace0, tag("Public key bits:"))(input)?;
        let (input, public_key_bits) = map_res(
            map(
                preceded(multispace0, take_until("Signature Information:")),
                |s: &str| {
                    s.trim()
                        .replace(" ", "")
                        .replace("\n", "")
                        .replace("\r", "")
                },
            ),
            base64::decode,
        )(input)?;
        let (input, signature_information) = preceded(
            multispace0,
            preceded(
                tag("Signature Information:"),
                many0(pair(
                    delimited(multispace0, map(take_until(":"), String::from), tag(":")),
                    delimited(multispace0, map(take_until("\n"), String::from), tag("\n")),
                )),
            ),
        )(input)?;
        let signature_information = signature_information.iter().cloned().collect();
        let (input, _) = multispace0(input)?;
        Ok((
            input,
            CertificateInfoResponse {
                certificate_name,
                validity_not_before,
                validity_not_after,
                public_key_bits,
                signature_information,
            },
        ))
    }
}
#[cfg(test)]
mod tests {
    use crate::command::*;
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
    async fn test_status_response() {
        let cmd = NFDStatusCommand;
        let res = cmd.execute().await.unwrap();
        let (remaining, parsed_res) = NFDStatusResponse::parse(&res).unwrap();
        println!("{:#?}", parsed_res);
        assert!(remaining.is_empty());
    }
    #[test]
    fn test_certificate() {
        let m = "  /test
  +->* /test/KEY/%A8C%0C%13%ADd%3B%9B
       +->* /test/KEY/%A8C%0C%13%ADd%3B%9B/self/%FD%00%00%01s%BF%E4U%3C
other";
        let (input, res) = Certificate::parse(m).unwrap();
        assert!(!res.is_default);
        assert_eq!(res.identity, "/test");
        assert_eq!(res.key, "/test/KEY/%A8C%0C%13%ADd%3B%9B");
        assert_eq!(
            res.certificate,
            "/test/KEY/%A8C%0C%13%ADd%3B%9B/self/%FD%00%00%01s%BF%E4U%3C"
        );
        assert_eq!(input, "other");
        let m = "* /test
                  +->* /test/KEY/%A8C%0C%13%ADd%3B%9B
                         +->* /test/KEY/%A8C%0C%13%ADd%3B%9B/self/%FD%00%00%01s%BF%E4U%3C
                         other";
        let (input, res) = Certificate::parse(m).unwrap();
        assert!(res.is_default);
        assert_eq!(res.identity, "/test");
        assert_eq!(res.key, "/test/KEY/%A8C%0C%13%ADd%3B%9B");
        assert_eq!(
            res.certificate,
            "/test/KEY/%A8C%0C%13%ADd%3B%9B/self/%FD%00%00%01s%BF%E4U%3C"
        );
        assert_eq!(input, "other");
    }
    #[async_std::test]
    async fn test_list_response() {
        let cmd = CertificateListCommand;
        let res = cmd.execute().await.unwrap();
        let (remaining, parsed_res) = CertificateListResponse::parse(&res).unwrap();
        println!("{:#?}", parsed_res);
        assert!(remaining.is_empty());
    }

    #[async_std::test]
    async fn test_certificate_info() {
        let certificate = "/test/KEY/%A8C%0C%13%ADd%3B%9B/self/%FD%00%00%01s%BF%E4U%3C".to_string();
        let cmd = CertificateInfoCommand { certificate };
        let res = cmd.execute().await.unwrap();
        let (remaining, parsed_res) = CertificateInfoResponse::parse(&res).unwrap();
        println!("{:#?}", parsed_res);
        assert!(remaining.is_empty());
    }
}
