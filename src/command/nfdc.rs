use super::*;
use serde::{Deserialize, Deserializer, Serialize};
use std::ffi::OsString;
use std::str::FromStr;
use url::Url;

pub enum NfdcCommand {
    Status,
}

impl Command for NfdcCommand {
    fn to_command(&self) -> Vec<OsString> {
        match self {
            NfdcCommand::Status => ["/usr/bin/nfdc", "status", "report", "xml"],
        }
        .iter()
        .map(OsString::from)
        .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NfdcStatus {
    pub general_status: GeneralStatus,
    pub channels: Channels,
    pub faces: Faces,
    pub fib: Fib,
    pub rib: Rib,
    pub cs: Cs,
    pub strategy_choices: StrategyChoices,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GeneralStatus {
    pub version: String,
    pub start_time: String,
    pub current_time: String,
    pub uptime: String,
    pub n_name_tree_entries: u64,
    pub n_fib_entries: u64,
    pub n_pit_entries: u64,
    pub n_measurements_entries: u64,
    pub n_cs_entries: u64,
    pub packet_counters: PacketCounters,
    pub n_satisfied_interests: u64,
    pub n_unsatisfied_interests: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PacketCounters {
    pub incoming_packets: PacketCountersEntry,
    pub outgoing_packets: PacketCountersEntry,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PacketCountersEntry {
    pub n_interests: u64,
    pub n_data: u64,
    pub n_nacks: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Channels {
    pub channel: Vec<Channel>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Channel {
    pub local_uri: Url,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Faces {
    pub face: Vec<Face>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Face {
    pub face_id: u64,
    pub remote_uri: String,
    pub local_uri: String,
    pub face_scope: String,
    pub face_persistency: String,
    pub link_type: String,
    pub congestion: Congestion,
    pub mtu: u64,
    pub flags: FaceFlags,
    pub packet_counters: PacketCounters,
    pub byte_counters: ByteCounters,
    pub interest_packet_size: PacketStatistics,
    pub data_packet_size: PacketStatistics,
    pub interest_packet_components: PacketStatistics,
    pub data_packet_components: PacketStatistics,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Congestion {
    pub base_marking_interval: Option<String>,
    pub default_threshold: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FaceFlags {
    pub local_fields_enabled: Option<LocalFieldsEnabled>,
    pub congestion_marking_enabled: Option<CongestionMarkingEnabled>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalFieldsEnabled;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CongestionMarkingEnabled;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ByteCounters {
    pub incoming_bytes: u64,
    pub outgoing_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PacketStatistics {
    pub min: u64,
    pub max: u64,
    #[serde(deserialize_with = "deserialize_f64")]
    pub avg: f64,
    #[serde(deserialize_with = "deserialize_f64")]
    pub std_dev: f64,
}

fn deserialize_f64<'de, D>(deser: D) -> Result<f64, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deser)?;
    match s.as_str() {
        "-nan" | "nan" => Ok(f64::NAN),
        s => f64::from_str(s).map_err(serde::de::Error::custom),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Fib {
    pub fib_entry: Vec<FibEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FibEntry {
    pub prefix: String,
    pub next_hops: NextHops,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NextHops {
    pub next_hop: Vec<NextHop>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NextHop {
    pub face_id: u64,
    pub cost: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Rib {
    pub rib_entry: Vec<RibEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RibEntry {
    pub prefix: String,
    pub routes: Routes,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Routes {
    pub route: Vec<Route>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Route {
    pub face_id: u64,
    pub origin: String,
    pub cost: u64,
    pub flags: RouteFlags,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RouteFlags {
    pub child_inherit: Option<ChildInherit>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChildInherit;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Cs {
    pub capacity: u64,
    pub admit_enabled: Option<AdmitEnabled>,
    pub serve_enabled: Option<ServeEnabled>,
    pub n_entries: u64,
    pub n_hits: u64,
    pub n_misses: u64,
    pub policy_name: String,
    pub min_size: u64,
    pub max_size: u64,
    pub average_size: f64,
    pub std_dev_size: f64,
    pub valid_signature_packets: u64,
    pub invalid_signature_packets: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdmitEnabled;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServeEnabled;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StrategyChoices {
    pub strategy_choice: Vec<StrategyChoice>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StrategyChoice {
    pub namespace: String,
    pub strategy: Strategy,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Strategy {
    pub name: String,
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn parse_example_output() {
        let output = include_str!("nfdc_report.xml");
        let parsed_output = serde_xml_rs::from_str::<NfdcStatus>(output).unwrap();
        println!("{:#?}", parsed_output);
    }

    #[ignore = "Must have a running system"]
    #[async_std::test]
    async fn parse_live_output() -> Result<(), Error> {
        let output = NfdcCommand::Status.run().await?;
        let parsed_output = serde_xml_rs::from_str::<NfdcStatus>(&output).unwrap();
        println!("{:#?}", parsed_output);
        Ok(())
    }
}
