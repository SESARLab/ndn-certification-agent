use async_std::prelude::{FutureExt as AsyncStdFutureExt, *};
use chrono::{self, DateTime, Utc};
use futures::future::{
    try_join, try_join3, try_join4, try_join5, try_join_all, TryFuture, TryJoinAll,
};
use futures::{FutureExt, TryFutureExt};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::str::FromStr;
use std::time::Duration;
use systemstat::{Platform, System};

const TIMEOUT: Duration = Duration::from_millis(1000);
const CS_ENTRY_SIZE: u64 = 8192;

use ndn_certification_agent::{
    command::{self, ndnsec, nfdc, Command},
    task::{self, Error, Evaluation, Logging, Logs, Measurement, PacketStatistics},
};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
enum Data {
    /// Total memory in Bytes
    HostTotalMemory(u64),
    NFDStatus(Box<nfdc::NfdcStatus>),
    CertificateList(Box<ndnsec::list::CertificateList>),
    CertificateInfo(Box<ndnsec::dump::CertificateInfo>),

    /// M1: CS policy name
    ///
    /// Which CS policy is enabled
    M1(String),
    /// M2: Maximum size of the CS
    ///
    /// How many entries can be stored in the CS
    M2(u64),
    /// M3: CS usage
    ///
    ///How many entries are stored in the CS
    M3(u64),
    /// M4: CS entry syze  statistics
    ///
    /// Minimum, maximum, mean and standard deviation of the CS entries memory usage
    M4(PacketStatistics),
    /// M5: Interest forwarding policy
    ///
    /// Which forwarding policy is used for each interest
    M5(HashMap<String, String>),
    /// PIT entries
    ///
    /// Number of pending interests stored in the PIT
    M6(HashMap<u64, i64>),

    /// Interest packet size statistics
    ///
    /// Minimum, maximum, mean and standard deviation of the incoming interest packets size
    M7(HashMap<u64, PacketStatistics>),
    /// Data packet size statistics
    ///
    /// Minimum, maximum, mean and standard deviation of the outgoing data packets size
    M8(HashMap<u64, PacketStatistics>),
    /// Interest packets components statistics
    ///
    /// Minimum, maximum, mean and standard deviation of the incoming interest packets number of components
    M9(HashMap<u64, PacketStatistics>),
    /// Data packets components statistics
    ///
    /// Minimum, maximum, mean and standard deviation of the outgoing data packets number of components
    M10(HashMap<u64, PacketStatistics>),

    /// Contents certifi cates validity
    ///
    /// Time interval of validity of the stored contents certificates
    M11(HashMap<String, (DateTime<Utc>, DateTime<Utc>)>),
    /// Default content certificate
    ///
    /// If and which default content certificate is set
    M12(Option<String>),
    /// Node memory
    ///
    /// The total amount of system memory of the NFD node
    M13(u64),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum Metrics {
    M1,
    M2,
    M3,
    M4,
    M5,
    M6,
    M7,
    M8,
    M9,
    M10,
    M11,
    M12,
    M13,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum Tasks {
    C1,
    C2,
    C3,
    C4,
    C5,
    C6,
    C7,
    C8,
    C9,
    C10,
    C11,
    C12,
    C13,
    C14,

    R1,
    R2,
    R3,
    R4,
    R5,
    R6,
    R7,

    P1,
    P2,
    P3,
}

type MeasurementResult = Result<Logging<Measurement<Data>, Metrics, Tasks, Data>, Error>;
type EvaluationResult = Result<Logging<Evaluation, Metrics, Tasks, Data>, Error>;

async fn nfdc_status() -> Result<nfdc::NfdcStatus, Error> {
    let ouptut = nfdc::NfdcCommand::Status.run().await?;
    let res = serde_xml_rs::from_str::<nfdc::NfdcStatus>(&ouptut).map_err(command::Error::from)?;
    Ok(res)
}

async fn ndnsec_list() -> Result<ndnsec::list::CertificateList, Error> {
    let ouptut = ndnsec::NDNSecCommand::List.run().await?;
    let res = ndnsec::list::CertificateList::from_str(&ouptut)?;
    Ok(res)
}

async fn ndnsec_info(identity: String) -> Result<ndnsec::dump::CertificateInfo, Error> {
    let ouptut = ndnsec::NDNSecCommand::Dump(identity).run().await?;
    let res = ndnsec::dump::CertificateInfo::from_str(&ouptut)?;
    Ok(res)
}

pub async fn host_total_memory() -> Result<u64, Error> {
    let sys = System::new();
    sys.memory()
        .map(|m| m.total.as_u64())
        .map_err(|e| command::Error::OutputError(format!("Could not read memory info: {}", e)))
        .map_err(Error::TaskError)
}

async fn m1<D1>(nfd_status_f: D1, index: u64) -> MeasurementResult
where
    D1: Future<Output = Result<nfdc::NfdcStatus, Error>>,
{
    let res: nfdc::NfdcStatus = nfd_status_f.timeout(TIMEOUT).await??;
    let data = Data::M1(res.cs.policy_name);
    let measurement = Measurement::new(data, index);
    let logs = Logs::default().with_measurement(measurement.clone(), Metrics::M1);
    Ok(Logging(measurement, logs))
}

async fn m2<D1>(nfd_status_f: D1, index: u64) -> MeasurementResult
where
    D1: Future<Output = Result<nfdc::NfdcStatus, Error>>,
{
    let res: nfdc::NfdcStatus = nfd_status_f.timeout(TIMEOUT).await??;
    let data = Data::M2(res.cs.max_size);
    let measurement = Measurement::new(data, index);
    let logs = Logs::default().with_measurement(measurement.clone(), Metrics::M2);
    Ok(Logging(measurement, logs))
}

async fn m3<D1>(nfd_status_f: D1, index: u64) -> MeasurementResult
where
    D1: Future<Output = Result<nfdc::NfdcStatus, Error>>,
{
    let res: nfdc::NfdcStatus = nfd_status_f.timeout(TIMEOUT).await??;
    let data = Data::M3(res.cs.n_entries);
    let measurement = Measurement::new(data, index);
    let logs = Logs::default().with_measurement(measurement.clone(), Metrics::M3);
    Ok(Logging(measurement, logs))
}

async fn m4<D1>(nfd_status_f: D1, index: u64) -> MeasurementResult
where
    D1: Future<Output = Result<nfdc::NfdcStatus, Error>>,
{
    let res: nfdc::NfdcStatus = nfd_status_f.timeout(TIMEOUT).await??;
    let data = Data::M4(PacketStatistics {
        min: res.cs.min_size,
        max: res.cs.max_size,
        avg: res.cs.average_size,
        std_dev: res.cs.std_dev_size,
    });
    let measurement = Measurement::new(data, index);
    let logs = Logs::default().with_measurement(measurement.clone(), Metrics::M4);
    Ok(Logging(measurement, logs))
}

async fn m5<D1>(nfd_status_f: D1, index: u64) -> MeasurementResult
where
    D1: Future<Output = Result<nfdc::NfdcStatus, Error>>,
{
    let res: nfdc::NfdcStatus = nfd_status_f.timeout(TIMEOUT).await??;
    let data = Data::M5(
        res.strategy_choices
            .strategy_choice
            .iter()
            .map(|sc| (sc.namespace.clone(), sc.strategy.name.clone()))
            .collect(),
    );
    let measurement = Measurement::new(data, index);
    let logs = Logs::default().with_measurement(measurement.clone(), Metrics::M5);
    Ok(Logging(measurement, logs))
}

async fn m6<D1>(nfd_status_f: D1, index: u64) -> MeasurementResult
where
    D1: Future<Output = Result<nfdc::NfdcStatus, Error>>,
{
    let res: nfdc::NfdcStatus = nfd_status_f.timeout(TIMEOUT).await??;
    let data = Data::M6(
        res.faces
            .face
            .iter()
            .map(|f| {
                (
                    f.face_id,
                    (f.packet_counters.incoming_packets.n_interests as i64
                        - f.packet_counters.outgoing_packets.n_data as i64
                        - f.packet_counters.outgoing_packets.n_nacks as i64),
                )
            })
            .collect(),
    );
    let measurement = Measurement::new(data, index);
    let logs = Logs::default().with_measurement(measurement.clone(), Metrics::M6);
    Ok(Logging(measurement, logs))
}

async fn m7<D1>(nfd_status_f: D1, index: u64) -> MeasurementResult
where
    D1: Future<Output = Result<nfdc::NfdcStatus, Error>>,
{
    let res: nfdc::NfdcStatus = nfd_status_f.timeout(TIMEOUT).await??;
    let data = Data::M7(
        res.faces
            .face
            .iter()
            .map(|f| (f.face_id, f.interest_packet_size.clone()))
            .collect(),
    );
    let measurement = Measurement::new(data, index);
    let logs = Logs::default().with_measurement(measurement.clone(), Metrics::M7);
    Ok(Logging(measurement, logs))
}

async fn m8<D1>(nfd_status_f: D1, index: u64) -> MeasurementResult
where
    D1: Future<Output = Result<nfdc::NfdcStatus, Error>>,
{
    let res: nfdc::NfdcStatus = nfd_status_f.timeout(TIMEOUT).await??;
    let data = Data::M8(
        res.faces
            .face
            .iter()
            .map(|f| (f.face_id, f.data_packet_size.clone()))
            .collect(),
    );
    let measurement = Measurement::new(data, index);
    let logs = Logs::default().with_measurement(measurement.clone(), Metrics::M8);
    Ok(Logging(measurement, logs))
}

async fn m9<D1>(nfd_status_f: D1, index: u64) -> MeasurementResult
where
    D1: Future<Output = Result<nfdc::NfdcStatus, Error>>,
{
    let res: nfdc::NfdcStatus = nfd_status_f.timeout(TIMEOUT).await??;
    let data = Data::M9(
        res.faces
            .face
            .iter()
            .map(|f| (f.face_id, f.interest_packet_components.clone()))
            .collect(),
    );
    let measurement = Measurement::new(data, index);
    let logs = Logs::default().with_measurement(measurement.clone(), Metrics::M9);
    Ok(Logging(measurement, logs))
}

async fn m10<D1>(nfd_status_f: D1, index: u64) -> MeasurementResult
where
    D1: Future<Output = Result<nfdc::NfdcStatus, Error>>,
{
    let res: nfdc::NfdcStatus = nfd_status_f.timeout(TIMEOUT).await??;
    let data = Data::M10(
        res.faces
            .face
            .iter()
            .map(|f| (f.face_id, f.data_packet_components.clone()))
            .collect(),
    );
    let measurement = Measurement::new(data, index);
    let logs = Logs::default().with_measurement(measurement.clone(), Metrics::M10);
    Ok(Logging(measurement, logs))
}

async fn m11<D1>(certificate_list_f: D1, index: u64) -> MeasurementResult
where
    D1: Future<Output = Result<ndnsec::list::CertificateList, Error>>,
{
    let certificate_list: ndnsec::list::CertificateList =
        certificate_list_f.timeout(TIMEOUT).await??;
    let certificate_info: Vec<(String, ndnsec::dump::CertificateInfo)> = try_join_all(
        certificate_list
            .certificates
            .iter()
            .map(|c| c.identity.clone())
            .map(|i| async {
                match ndnsec_info(i.clone()).timeout(TIMEOUT).await {
                    Err(t) => Err(Error::TimeoutError(t)),
                    Ok(Err(e)) => Err(e),
                    Ok(Ok(d)) => Ok((i, d)),
                }
            }),
    )
    .await?;
    let data = Data::M11(
        certificate_info
            .iter()
            .map(|(i, d)| (i.clone(), (d.validity_not_before, d.validity_not_after)))
            .collect(),
    );
    let measurement = Measurement::new(data, index);
    let logs = Logs::default().with_measurement(measurement.clone(), Metrics::M11);
    Ok(Logging(measurement, logs))
}

async fn m12<D1>(certificate_list_f: D1, index: u64) -> MeasurementResult
where
    D1: Future<Output = Result<ndnsec::list::CertificateList, Error>>,
{
    let res: ndnsec::list::CertificateList = certificate_list_f.timeout(TIMEOUT).await??;
    let data = Data::M12(
        res.certificates
            .iter()
            .filter(|c| c.is_default)
            .map(|c| c.certificate.clone())
            .next(),
    );
    let measurement = Measurement::new(data, index);
    let logs = Logs::default().with_measurement(measurement.clone(), Metrics::M12);
    Ok(Logging(measurement, logs))
}

async fn m13<D1>(host_total_memory_f: D1, index: u64) -> MeasurementResult
where
    D1: Future<Output = Result<u64, Error>>,
{
    let res = host_total_memory_f.timeout(TIMEOUT).await??;
    let data = Data::M13(res);
    let measurement = Measurement::new(data, index);
    let logs = Logs::default().with_measurement(measurement.clone(), Metrics::M13);
    Ok(Logging(measurement, logs))
}

async fn c1<M1>(m1: M1, index: u64) -> EvaluationResult
where
    M1: Future<Output = MeasurementResult>,
{
    let Logging(measurement, logs) = m1.await?;
    let data = match measurement.data {
        Data::M1(cs_policy_name) if cs_policy_name == "lru" => Ok(true),
        Data::M1(_) => Ok(false),
        _ => Err(Error::EvaluationError(
            "Wrong dependency task provided".to_string(),
        )),
    }?;
    let evaluation = Evaluation::new(data, index);
    let logs = logs.with_evaluation(evaluation.clone(), Tasks::C1);
    Ok(Logging(evaluation, logs))
}

async fn c2<M2, M13>(m2: M2, m13: M13, index: u64) -> EvaluationResult
where
    M2: Future<Output = MeasurementResult>,
    M13: Future<Output = MeasurementResult>,
{
    let (Logging(m2_measurement, m2_logs), Logging(m13_measurement, m13_logs)) =
        try_join(m2, m13).await?;
    let data = match (m2_measurement.data, m13_measurement.data) {
        (Data::M2(cs_entries), Data::M13(total_memory))
            if total_memory * 80 / 100 >= cs_entries * CS_ENTRY_SIZE
                && cs_entries * CS_ENTRY_SIZE >= total_memory / 10 =>
        {
            Ok(true)
        }

        (Data::M2(_), Data::M13(_)) => Ok(false),
        _ => Err(Error::EvaluationError(
            "Wrong dependency tasks provided".to_string(),
        )),
    }?;
    let evaluation = Evaluation::new(data, index);
    let logs = m2_logs
        .merge(&m13_logs)
        .with_evaluation(evaluation.clone(), Tasks::C2);
    Ok(Logging(evaluation, logs))
}

async fn c3<M2>(m2: M2, index: u64) -> EvaluationResult
where
    M2: Future<Output = MeasurementResult>,
{
    let Logging(measurement, logs) = m2.await?;
    let data = match measurement.data {
        Data::M2(cs_entries) if cs_entries <= 100000 => Ok(true),
        Data::M2(_) => Ok(false),
        _ => Err(Error::EvaluationError(
            "Wrong dependency task provided".to_string(),
        )),
    }?;
    let evaluation = Evaluation::new(data, index);
    let logs = logs.with_evaluation(evaluation.clone(), Tasks::C3);
    Ok(Logging(evaluation, logs))
}

async fn c4<M2, M3>(m2: M2, m3: M3, index: u64) -> EvaluationResult
where
    M2: Future<Output = MeasurementResult>,
    M3: Future<Output = MeasurementResult>,
{
    let (Logging(m2_measurement, m2_logs), Logging(m3_measurement, m3_logs)) =
        try_join(m2, m3).await?;
    let value = match (m2_measurement.data, m3_measurement.data) {
        (Data::M2(cs_entries), Data::M3(cs_usage)) if cs_usage >= cs_entries * 80 / 100 => Ok(true),
        (Data::M2(_), Data::M3(_)) => Ok(false),
        _ => Err(Error::EvaluationError(
            "Wrong dependency tasks provided".to_string(),
        )),
    }?;
    let evaluation = Evaluation::new(value, index);
    let logs = m2_logs
        .merge(&m3_logs)
        .with_evaluation(evaluation.clone(), Tasks::C4);
    Ok(Logging(evaluation, logs))
}

async fn c5<M3>(m3: M3, index: u64) -> EvaluationResult
where
    M3: Future<Output = MeasurementResult>,
{
    let Logging(measurement, logs) = m3.await?;

    let value = match (
        index,
        measurement.data,
        logs.measurements_index.get(&Metrics::M3),
    ) {
        // Not enough measurements
        (i, _, _) if i < 4 => Ok(false),
        // Valid data
        (_, Data::M3(_), Some(measurements)) => {
            let cs_usages: Vec<u64> = (index - 4..=index)
                .filter_map(|i| measurements.get(&i))
                .filter_map(|d| if let Data::M3(v) = d { Some(v) } else { None })
                .cloned()
                .collect();
            let mean = cs_usages.iter().cloned().sum::<u64>() as f64 / cs_usages.len() as f64;
            let std_dev = (cs_usages
                .iter()
                .fold(0_f64, |acc, new| acc + (*new as f64 - mean).powi(2))
                / (cs_usages.len() as u64 - 1) as f64)
                .sqrt();
            // Finally check if std_dev across measurements is less than 5.0
            Ok(std_dev < 5.0f64)
        }
        _ => Err(Error::EvaluationError(
            "Wrong dependency tasks provided".to_string(),
        )),
    }?;
    let evaluation = Evaluation::new(value, index);
    let logs = logs.with_evaluation(evaluation.clone(), Tasks::C5);
    Ok(Logging(evaluation, logs))
}

async fn c6<M4>(m4: M4, index: u64) -> EvaluationResult
where
    M4: Future<Output = MeasurementResult>,
{
    let Logging(measurement, logs) = m4.await?;
    let value = match measurement.data {
        Data::M4(v) if v.std_dev <= 5.0_f64 => Ok(true),
        Data::M4(_) => Ok(false),
        _ => Err(Error::EvaluationError(
            "Wrong dependency task provided".to_string(),
        )),
    }?;
    let evaluation = Evaluation::new(value, index);
    let logs = logs.with_evaluation(evaluation.clone(), Tasks::C6);
    Ok(Logging(evaluation, logs))
}

async fn c7<M4>(m4: M4, index: u64) -> EvaluationResult
where
    M4: Future<Output = MeasurementResult>,
{
    let Logging(measurement, logs) = m4.await?;
    let value = match measurement.data {
        Data::M4(v) if v.avg >= 20_f64 => Ok(true),
        Data::M4(_) => Ok(false),
        _ => Err(Error::EvaluationError(
            "Wrong dependency task provided".to_string(),
        )),
    }?;
    let evaluation = Evaluation::new(value, index);
    let logs = logs.with_evaluation(evaluation.clone(), Tasks::C7);
    Ok(Logging(evaluation, logs))
}

async fn c8<M6>(m6: M6, index: u64) -> EvaluationResult
where
    M6: Future<Output = MeasurementResult>,
{
    let Logging(measurement, logs) = m6.await?;
    let value = match measurement.data {
        Data::M6(v) => Ok(v.values().all(|v| *v < 100)),
        _ => Err(Error::EvaluationError(
            "Wrong dependency task provided".to_string(),
        )),
    }?;
    let evaluation = Evaluation::new(value, index);
    let logs = logs.with_evaluation(evaluation.clone(), Tasks::C8);
    Ok(Logging(evaluation, logs))
}

async fn c9<M7>(m7: M7, index: u64) -> EvaluationResult
where
    M7: Future<Output = MeasurementResult>,
{
    let Logging(measurement, logs) = m7.await?;
    let value = match measurement.data {
        Data::M7(v) => Ok(v.values().all(|s| s.min >= 10)),
        _ => Err(Error::EvaluationError(
            "Wrong dependency task provided".to_string(),
        )),
    }?;
    let evaluation = Evaluation::new(value, index);
    let logs = logs.with_evaluation(evaluation.clone(), Tasks::C9);
    Ok(Logging(evaluation, logs))
}

async fn c10<M9>(m9: M9, index: u64) -> EvaluationResult
where
    M9: Future<Output = MeasurementResult>,
{
    let Logging(measurement, logs) = m9.await?;
    let value = match measurement.data {
        Data::M9(v) => Ok(v.values().all(|s| 3.0 < s.avg && s.avg < 10.0)),
        _ => Err(Error::EvaluationError(
            "Wrong dependency task provided".to_string(),
        )),
    }?;
    let evaluation = Evaluation::new(value, index);
    let logs = logs.with_evaluation(evaluation.clone(), Tasks::C10);
    Ok(Logging(evaluation, logs))
}

async fn c11<M8>(m8: M8, index: u64) -> EvaluationResult
where
    M8: Future<Output = MeasurementResult>,
{
    let Logging(measurement, logs) = m8.await?;
    let value = match measurement.data {
        Data::M8(v) => Ok(v.values().all(|s| s.min >= 10)),
        _ => Err(Error::EvaluationError(
            "Wrong dependency task provided".to_string(),
        )),
    }?;
    let evaluation = Evaluation::new(value, index);
    let logs = logs.with_evaluation(evaluation.clone(), Tasks::C11);
    Ok(Logging(evaluation, logs))
}

async fn c12<M10>(m10: M10, index: u64) -> EvaluationResult
where
    M10: Future<Output = MeasurementResult>,
{
    let Logging(measurement, logs) = m10.await?;
    let value = match measurement.data {
        Data::M10(v) => Ok(v.values().all(|s| 3.0 < s.avg && s.avg < 10.0)),
        _ => Err(Error::EvaluationError(
            "Wrong dependency task provided".to_string(),
        )),
    }?;
    let evaluation = Evaluation::new(value, index);
    let logs = logs.with_evaluation(evaluation.clone(), Tasks::C12);
    Ok(Logging(evaluation, logs))
}

async fn c13<M11>(m11: M11, index: u64) -> EvaluationResult
where
    M11: Future<Output = MeasurementResult>,
{
    let Logging(measurement, logs) = m11.await?;
    let now = Utc::now();
    let value = match measurement.data {
        Data::M11(v) => Ok(v.values().all(|s| s.0 < now && now < s.1)),
        _ => Err(Error::EvaluationError(
            "Wrong dependency task provided".to_string(),
        )),
    }?;
    let evaluation = Evaluation::new(value, index);
    let logs = logs.with_evaluation(evaluation.clone(), Tasks::C13);
    Ok(Logging(evaluation, logs))
}

async fn c14<M12>(m12: M12, index: u64) -> EvaluationResult
where
    M12: Future<Output = MeasurementResult>,
{
    let Logging(measurement, logs) = m12.await?;
    let value = match measurement.data {
        Data::M12(v) => Ok(v.is_some()),
        _ => Err(Error::EvaluationError(
            "Wrong dependency task provided".to_string(),
        )),
    }?;
    let evaluation = Evaluation::new(value, index);
    let logs = logs.with_evaluation(evaluation.clone(), Tasks::C14);
    Ok(Logging(evaluation, logs))
}

async fn r1<C1, C2, C3>(c1: C1, c2: C2, c3: C3, index: u64) -> EvaluationResult
where
    C1: Future<Output = EvaluationResult>,
    C2: Future<Output = EvaluationResult>,
    C3: Future<Output = EvaluationResult>,
{
    let (Logging(eval_1, logs_1), Logging(eval_2, logs_2), Logging(eval_3, logs_3)) =
        try_join3(c1, c2, c3).await?;
    let value = eval_1.evaluation && eval_2.evaluation && eval_3.evaluation;
    let evaluation = Evaluation::new(value, index);
    let logs = logs_1
        .merge(&logs_2)
        .merge(&logs_3)
        .with_evaluation(evaluation.clone(), Tasks::R1);
    Ok(Logging(evaluation, logs))
}

async fn r2<C4, C5, C6, C7>(c4: C4, c5: C5, c6: C6, c7: C7, index: u64) -> EvaluationResult
where
    C4: Future<Output = EvaluationResult>,
    C5: Future<Output = EvaluationResult>,
    C6: Future<Output = EvaluationResult>,
    C7: Future<Output = EvaluationResult>,
{
    let (Logging(_, logs_4), Logging(_, logs_5), Logging(_, logs_6), Logging(_, logs_7)) =
        try_join4(c4, c5, c6, c7).await?;

    let logs = logs_4.merge(&logs_5).merge(&logs_6).merge(&logs_7);
    let now = Utc::now();
    let value = [Tasks::C4, Tasks::C5, Tasks::C6, Tasks::C7]
        .iter()
        .all(|t| {
            logs.evaluations_timestamp
                .get(t)
                .map(|eval| {
                    eval.iter()
                        .filter(|(k, _)| **k >= (now + chrono::Duration::minutes(-10)))
                        .all(|(_, v)| *v)
                })
                .unwrap_or(false)
        });
    let evaluation = Evaluation::new(value, index);
    let logs = logs.with_evaluation(evaluation.clone(), Tasks::R2);
    Ok(Logging(evaluation, logs))
}

async fn r3<C8>(c8: C8, index: u64) -> EvaluationResult
where
    C8: Future<Output = EvaluationResult>,
{
    let Logging(_, logs) = c8.await?;
    let now = Utc::now();
    let value = logs
        .evaluations_timestamp
        .get(&Tasks::C8)
        .map(|eval| {
            eval.iter()
                .filter(|(k, _)| **k >= (now + chrono::Duration::minutes(-10)))
                .all(|(_, v)| *v)
        })
        .unwrap_or(false);
    let evaluation = Evaluation::new(value, index);
    let logs = logs.with_evaluation(evaluation.clone(), Tasks::R3);
    Ok(Logging(evaluation, logs))
}

async fn r4<C9, C10>(c9: C9, c10: C10, index: u64) -> EvaluationResult
where
    C9: Future<Output = EvaluationResult>,
    C10: Future<Output = EvaluationResult>,
{
    let (Logging(_, logs_9), Logging(_, logs_10)) = try_join(c9, c10).await?;
    let logs = logs_9.merge(&logs_10);
    let now = Utc::now();
    let value = [Tasks::C9, Tasks::C10].iter().all(|t| {
        logs.evaluations_timestamp
            .get(t)
            .map(|eval| {
                eval.iter()
                    .filter(|(k, _)| **k >= (now + chrono::Duration::minutes(-10)))
                    .all(|(_, v)| *v)
            })
            .unwrap_or(false)
    });
    let evaluation = Evaluation::new(value, index);
    let logs = logs.with_evaluation(evaluation.clone(), Tasks::R4);
    Ok(Logging(evaluation, logs))
}

async fn r5<C11, C12>(c11: C11, c12: C12, index: u64) -> EvaluationResult
where
    C11: Future<Output = EvaluationResult>,
    C12: Future<Output = EvaluationResult>,
{
    let (Logging(_, logs_11), Logging(_, logs_12)) = try_join(c11, c12).await?;
    let logs = logs_11.merge(&logs_12);
    let now = Utc::now();
    let value = [Tasks::C11, Tasks::C12].iter().all(|t| {
        logs.evaluations_timestamp
            .get(t)
            .map(|eval| {
                eval.iter()
                    .filter(|(k, _)| **k >= (now + chrono::Duration::minutes(-10)))
                    .all(|(_, v)| *v)
            })
            .unwrap_or(false)
    });
    let evaluation = Evaluation::new(value, index);
    let logs = logs.with_evaluation(evaluation.clone(), Tasks::R5);
    Ok(Logging(evaluation, logs))
}

async fn r6<C13>(c13: C13, index: u64) -> EvaluationResult
where
    C13: Future<Output = EvaluationResult>,
{
    let Logging(_, logs) = c13.await?;
    let now = Utc::now();
    let value = logs
        .evaluations_timestamp
        .get(&Tasks::C13)
        .map(|eval| {
            eval.iter()
                .filter(|(k, _)| **k >= (now + chrono::Duration::minutes(-10)))
                .all(|(_, v)| *v)
        })
        .unwrap_or(false);
    let evaluation = Evaluation::new(value, index);
    let logs = logs.with_evaluation(evaluation.clone(), Tasks::R6);
    Ok(Logging(evaluation, logs))
}

async fn r7<C14>(c14: C14, index: u64) -> EvaluationResult
where
    C14: Future<Output = EvaluationResult>,
{
    let Logging(_, logs) = c14.await?;
    let now = Utc::now();
    let value = logs
        .evaluations_timestamp
        .get(&Tasks::C14)
        .map(|eval| {
            eval.iter()
                .filter(|(k, _)| **k >= (now + chrono::Duration::minutes(-10)))
                .all(|(_, v)| *v)
        })
        .unwrap_or(false);
    let evaluation = Evaluation::new(value, index);
    let logs = logs.with_evaluation(evaluation.clone(), Tasks::R7);
    Ok(Logging(evaluation, logs))
}

async fn p1<R1, R2, R3, R4, R5>(
    r1: R1,
    r2: R2,
    r3: R3,
    r4: R4,
    r5: R5,
    index: u64,
) -> EvaluationResult
where
    R1: Future<Output = EvaluationResult>,
    R2: Future<Output = EvaluationResult>,
    R3: Future<Output = EvaluationResult>,
    R4: Future<Output = EvaluationResult>,
    R5: Future<Output = EvaluationResult>,
{
    let (
        Logging(_, logs_1),
        Logging(_, logs_2),
        Logging(_, logs_3),
        Logging(_, logs_4),
        Logging(_, logs_5),
    ) = try_join5(r1, r2, r3, r4, r5).await?;
    let logs = logs_1
        .merge(&logs_2)
        .merge(&logs_3)
        .merge(&logs_4)
        .merge(&logs_5);
    let now = Utc::now();
    let value = [Tasks::R1, Tasks::R2, Tasks::R3, Tasks::R4, Tasks::R5]
        .iter()
        .all(|t| {
            logs.evaluations_timestamp
                .get(t)
                .map(|eval| {
                    eval.iter()
                        .filter(|(k, _)| **k >= (now + chrono::Duration::minutes(-10)))
                        .all(|(_, v)| *v)
                })
                .unwrap_or(false)
        });
    let evaluation = Evaluation::new(value, index);
    let logs = logs.with_evaluation(evaluation.clone(), Tasks::P1);
    Ok(Logging(evaluation, logs))
}

async fn p2<R6, R7>(r6: R6, r7: R7, index: u64) -> EvaluationResult
where
    R6: Future<Output = EvaluationResult>,
    R7: Future<Output = EvaluationResult>,
{
    let (Logging(_, logs_6), Logging(_, logs_7)) = try_join(r6, r7).await?;
    let logs = logs_6.merge(&logs_7);
    let now = Utc::now();
    let value = [Tasks::R6, Tasks::R7].iter().all(|t| {
        logs.evaluations_timestamp
            .get(t)
            .map(|eval| {
                eval.iter()
                    .filter(|(k, _)| **k >= (now + chrono::Duration::minutes(-10)))
                    .all(|(_, v)| *v)
            })
            .unwrap_or(false)
    });
    let evaluation = Evaluation::new(value, index);
    let logs = logs.with_evaluation(evaluation.clone(), Tasks::P2);
    Ok(Logging(evaluation, logs))
}

async fn p3<R6, R7>(r6: R6, r7: R7, index: u64) -> EvaluationResult
where
    R6: Future<Output = EvaluationResult>,
    R7: Future<Output = EvaluationResult>,
{
    let (Logging(_, logs_6), Logging(_, logs_7)) = try_join(r6, r7).await?;
    let logs = logs_6.merge(&logs_7);
    let now = Utc::now();
    let value = [Tasks::R6, Tasks::R7].iter().all(|t| {
        logs.evaluations_timestamp
            .get(t)
            .map(|eval| {
                eval.iter()
                    .filter(|(k, _)| **k >= (now + chrono::Duration::minutes(-10)))
                    .all(|(_, v)| *v)
            })
            .unwrap_or(false)
    });
    let evaluation = Evaluation::new(value, index);
    let logs = logs.with_evaluation(evaluation.clone(), Tasks::P3);
    Ok(Logging(evaluation, logs))
}

#[async_std::main]
async fn main() {
    // let mut logs = Logs::default();
    let index = 0u64;

    let host_total_memory_f = host_total_memory().shared();
    let nfd_status_f = nfdc_status().shared();
    let certificate_list_f = ndnsec_list().shared();

    let m1_f = m1(nfd_status_f.clone(), index).shared();
    let m2_f = m2(nfd_status_f.clone(), index).shared();
    let m3_f = m3(nfd_status_f.clone(), index).shared();
    let m4_f = m4(nfd_status_f.clone(), index).shared();
    // let m5_f = m5(nfd_status_f.clone(), index).shared();
    let m6_f = m6(nfd_status_f.clone(), index).shared();
    let m7_f = m7(nfd_status_f.clone(), index).shared();
    let m8_f = m8(nfd_status_f.clone(), index).shared();
    let m9_f = m9(nfd_status_f.clone(), index).shared();
    let m10_f = m10(nfd_status_f, index).shared();
    let m11_f = m11(certificate_list_f.clone(), index).shared();
    let m12_f = m12(certificate_list_f, index).shared();
    let m13_f = m13(host_total_memory_f, index).shared();

    let c1_f = c1(m1_f, index).shared();
    let c2_f = c2(m2_f.clone(), m13_f.clone(), index).shared();
    let c3_f = c3(m2_f.clone(), index).shared();
    let c4_f = c4(m2_f, m3_f.clone(), index).shared();
    let c5_f = c5(m3_f.clone(), index).shared();
    let c6_f = c6(m4_f.clone(), index).shared();
    let c7_f = c7(m4_f, index).shared();
    let c8_f = c8(m6_f, index).shared();
    let c9_f = c9(m7_f, index).shared();
    let c10_f = c10(m9_f, index).shared();
    let c11_f = c11(m8_f, index).shared();
    let c12_f = c12(m10_f, index).shared();
    let c13_f = c13(m11_f, index).shared();
    let c14_f = c14(m12_f, index).shared();

    let r1_f = r1(c1_f, c2_f, c3_f, index).shared();
    let r2_f = r2(c4_f, c5_f, c6_f, c7_f, index).shared();
    let r3_f = r3(c8_f, index).shared();
    let r4_f = r4(c9_f, c10_f, index).shared();
    let r5_f = r5(c11_f, c12_f, index).shared();
    let r6_f = r6(c13_f, index).shared();
    let r7_f = r7(c14_f, index).shared();

    let p1_f = p1(r1_f, r2_f, r3_f, r4_f, r5_f, index).shared();
    let p2_f = p2(r6_f.clone(), r7_f.clone(), index).shared();
    let p3_f = p3(r6_f, r7_f, index).shared();

    match try_join3(p1_f, p2_f, p3_f).await {
        Ok(v) => {
            let (
                Logging(evaluation_1, logs_1),
                Logging(evaluation_2, logs_2),
                Logging(evaluation_3, logs_3),
            ) = v;
            let evaluation =
                evaluation_1.evaluation && evaluation_2.evaluation && evaluation_3.evaluation;
            let logs = logs_1.merge(&logs_2).merge(&logs_3);
//             println!("{:?}", logs.evaluations_index.iter().map(|(k,v)|
// (k,v.iter().collect::<Vec<_>>())).collect::<Vec<_>>());
            println!("{:#?}", logs);
        }
        Err(e) => eprintln!("{}", e),
    }
}
