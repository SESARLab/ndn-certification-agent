use nom::{
    bytes::complete::{is_not, tag, take_until},
    character::complete::multispace0,
    combinator::{map, opt},
    multi::many0,
    sequence::{delimited, preceded},
    IResult,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertificateList {
    pub certificates: Vec<Certificate>,
}

impl CertificateList {
    pub fn parse(input: &str) -> IResult<&str, Self> {
        let (input, certificates) = preceded(multispace0, many0(Certificate::parse))(input)?;
        Ok((input, CertificateList { certificates }))
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
		use crate::command::ndnsec::*;
		use super::*;
  	use std::time::Duration;
  	use async_std::prelude::FutureExt;

    #[test]
    fn parse_example_output() {
        let output = include_str!("list.txt");
        let parsed_output = CertificateList::parse(output).unwrap();
        println!("{:#?}", parsed_output);
        assert_eq!(parsed_output.0, "");
    }

		#[ignore = "Must have a running system"]
    #[async_std::test]
    async fn parse_live_output() -> Result<(), Box<dyn std::error::Error>> {
        let output = NDNSecCommand::List.run().timeout(Duration::from_millis(1000)).await??;
        let parsed_output = CertificateList::parse(&output).unwrap();
        println!("{:#?}", parsed_output);
        assert_eq!(parsed_output.0, "");
        Ok(())
    }
}
