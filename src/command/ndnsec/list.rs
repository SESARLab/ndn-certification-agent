use crate::command::Error;
use nom::{
    bytes::complete::{is_not, tag, take_until},
    character::complete::multispace0,
    combinator::{map, opt},
    multi::many0,
    sequence::{delimited, preceded},
    IResult,
};
use serde::{Deserialize, Serialize};
use std::str::FromStr;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertificateList {
    pub certificates: Vec<Certificate>,
}

impl CertificateList {
    fn parse(input: &str) -> IResult<&str, Self> {
        let (input, certificates) = preceded(multispace0, many0(Certificate::parse))(input)?;
        Ok((input, CertificateList { certificates }))
    }
}
impl FromStr for CertificateList {
    type Err = Error;
    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let (rest, res) =
            Self::parse(input).map_err(|e| Error::NOMParsingError(format!("{}", e)))?;
        debug_assert!(rest.is_empty());
        Ok(res)
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

#[cfg(test)]
mod test {
    use super::*;
    use crate::command::ndnsec::*;
    use async_std::prelude::FutureExt;
    use std::time::Duration;

    #[test]
    fn parse_example_output() {
        let output = include_str!("list.txt");
        let parsed_output = CertificateList::from_str(output).unwrap();
        println!("{:#?}", parsed_output);
    }

    #[ignore = "Must have a running system"]
    #[async_std::test]
    async fn parse_live_output() -> Result<(), Box<dyn std::error::Error>> {
        let output = NDNSecCommand::List
            .run()
            .timeout(Duration::from_millis(1000))
            .await??;
        let parsed_output = CertificateList::from_str(&output).unwrap();
        println!("{:#?}", parsed_output);
        Ok(())
    }
}
