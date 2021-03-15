use nom::{
    bytes::complete::{tag, take, take_until},
    character::complete::multispace0,
    combinator::{map, map_res},
    sequence::{delimited, pair, preceded, tuple},
    multi::many0,
    IResult
};
use serde::{Serialize,Deserialize};
use std::collections::HashMap;
use chrono::{DateTime, Utc, TimeZone};
use std::str::FromStr;
use crate::command::Error;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertificateInfo {
    pub certificate_name: String,
    pub validity_not_before: DateTime<Utc>,
    pub validity_not_after: DateTime<Utc>,
    pub public_key_bits: Vec<u8>,
    pub signature_information: HashMap<String, String>,
}
impl CertificateInfo {
    pub fn parse(input: &str) -> IResult<&str, Self> {
        let (input, _) = preceded(multispace0, tag("Certificate name:"))(input)?;
        let (input, certificate_name) =
            preceded(multispace0, map(take_until("\n"), String::from))(input)?;
        let (input, _) = preceded(multispace0, tag("Validity:"))(input)?;
        let (input, _) = preceded(multispace0, tag("NotBefore: "))(input)?;
        let (input, validity_not_before) = preceded(
            multispace0,
            map_res(
                tuple((
                    map_res(take(4u64), i32::from_str),
                    map_res(take(2u64), u32::from_str),
                    map_res(take(2u64), u32::from_str),
                    tag("T"),
                    map_res(take(2u64), u32::from_str),
                    map_res(take(2u64), u32::from_str),
                    map_res(take(2u64), u32::from_str),
                )),
                |(year, month, day, _, hour, minute, second)| {
                    Utc.ymd_opt(year, month, day)
                        .and_hms_opt(hour, minute, second)
                        .single()
                        .ok_or_else(|| Error::NOMParsingError(String::from("Invalid ISO 8601")))
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
                        .ok_or_else(|| Error::NOMParsingError(String::from("Invalid ISO 8601")))
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
            CertificateInfo {
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
mod test {
    use super::*;
    use crate::command::{Command, ndnsec::NDNSecCommand};
    use std::time::Duration;
    use async_std::prelude::FutureExt;

		#[test]
    fn parse_example_output() {
        let output = include_str!("dump.txt");
        let (rest, parsed_output) = CertificateInfo::parse(output).unwrap();
        assert!(rest.is_empty());
        println!("{:?}", parsed_output);
    }

		#[ignore = "Must have a running system"]
    #[async_std::test]
    async fn parse_live_output() -> Result<(), Box<dyn std::error::Error>> {
      let identity = String::from("test");
        let output = NDNSecCommand::Dump(identity).run().timeout(Duration::from_millis(1000)).await??;
        let (rest, parsed_output) = CertificateInfo::parse(&output).unwrap();
        assert!(rest.is_empty());
        println!("{:?}", parsed_output);
        Ok(())
    }

}
