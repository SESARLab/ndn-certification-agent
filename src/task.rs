use crate::command;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::hash::Hash;
use thiserror::Error as ThisError;

#[derive(Debug, Clone, ThisError)]
pub enum Error {
    #[error(transparent)]
    TaskError(#[from] command::Error),

    #[error(transparent)]
    TimeoutError(#[from] async_std::future::TimeoutError),

    #[error("{0}")]
    EvaluationError(String),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Measurement<Data> {
    pub data: Data,
    pub index: u64,
    pub timestamp: DateTime<Utc>,
}

impl<Data> Measurement<Data> {
    pub fn new(data: Data, index: u64) -> Self {
        Self {
            data,
            index,
            timestamp: Utc::now(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Evaluation {
    pub value: bool,
    pub index: u64,
    pub timestamp: DateTime<Utc>,
}

impl Evaluation {
    pub fn new(evaluation: bool, index: u64) -> Self {
        Self {
            value: evaluation,
            index,
            timestamp: Utc::now(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Logs<Metrics, Tasks, Data>
where
    Metrics: Hash + Eq,
    Tasks: Hash + Eq,
{
    pub measurements_index: HashMap<Metrics, VecDeque<(u64, Data)>>,
    pub measurements_timestamp: HashMap<Metrics, VecDeque<(DateTime<Utc>, Data)>>,
    pub evaluations_index: HashMap<Tasks, VecDeque<(u64, bool)>>,
    pub evaluations_timestamp: HashMap<Tasks, VecDeque<(DateTime<Utc>, bool)>>,
    pub duration_index: HashMap<u64, i64>,
}

impl<Metrics, Tasks, Data> Default for Logs<Metrics, Tasks, Data>
where
    Metrics: Hash + Eq,
    Tasks: Hash + Eq,
{
    fn default() -> Self {
        Logs {
            measurements_index: HashMap::default(),
            measurements_timestamp: HashMap::default(),
            evaluations_index: HashMap::default(),
            evaluations_timestamp: HashMap::default(),
            duration_index: HashMap::default(),
        }
    }
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Table<Metrics, Tasks, Data>
where
    Metrics: Hash + Eq,
    Tasks: Hash + Eq,
{
    pub measurements_index: HashMap<Metrics, HashMap<u64, Data>>,
    pub measurements_timestamp: HashMap<Metrics, HashMap<DateTime<Utc>, Data>>,
    pub evaluations_index: HashMap<Tasks, HashMap<u64, bool>>,
    pub evaluations_timestamp: HashMap<Tasks, HashMap<DateTime<Utc>, bool>>,
    pub duration_index: HashMap<u64, i64>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Logging<T, Metrics, Tasks, Data>(pub T, pub Logs<Metrics, Tasks, Data>)
where
    Metrics: Hash + Eq,
    Tasks: Hash + Eq;

impl<Metrics, Tasks, Data> Logs<Metrics, Tasks, Data>
where
    Metrics: Clone + Hash + Eq,
    Tasks: Clone + Hash + Eq,
    Data: Clone,
{
    pub fn with_measurement(
        &self,
        measurement: Measurement<Data>,
        metric: Metrics,
    ) -> Logs<Metrics, Tasks, Data> {
        let mut res = self.clone();
        res.measurements_index
            .entry(metric.clone())
            .or_insert_with(Default::default)
            .push_back((measurement.index, measurement.data.clone()));
        res.measurements_timestamp
            .entry(metric)
            .or_insert_with(Default::default)
            .push_back((measurement.timestamp, measurement.data));
        res
    }

    pub fn insert_measurement(
        &mut self,
        measurement: Measurement<Data>,
        metric: Metrics,
    ) -> &mut Self {
        self.measurements_index
            .entry(metric.clone())
            .or_insert_with(Default::default)
            .push_back((measurement.index, measurement.data.clone()));
        self.measurements_timestamp
            .entry(metric)
            .or_insert_with(Default::default)
            .push_back((measurement.timestamp, measurement.data));
        self
    }

    pub fn with_evaluation(
        &self,
        evaluation: Evaluation,
        task: Tasks,
    ) -> Logs<Metrics, Tasks, Data> {
        let mut res = self.clone();
        res.evaluations_index
            .entry(task.clone())
            .or_insert_with(Default::default)
            .push_back((evaluation.index, evaluation.value));
        res.evaluations_timestamp
            .entry(task)
            .or_insert_with(Default::default)
            .push_back((evaluation.timestamp, evaluation.value));
        res
    }

    pub fn insert_evaluation(&mut self, evaluation: Evaluation, task: Tasks) -> &mut Self {
        self.evaluations_index
            .entry(task.clone())
            .or_insert_with(Default::default)
            .push_back((evaluation.index, evaluation.value));
        self.evaluations_timestamp
            .entry(task)
            .or_insert_with(Default::default)
            .push_back((evaluation.timestamp, evaluation.value));
        self
    }

    pub fn with_duration(&self, duration: i64, index: u64) -> Logs<Metrics, Tasks, Data> {
        let mut res = self.clone();
        res.duration_index.insert(index, duration);
        res
    }

    pub fn insert_duration(&mut self, duration: i64, index: u64) -> &mut Self {
        self.duration_index.insert(index, duration);
        self
    }

    pub fn merge(&self, other: &Self) -> Self {
        let mut res = self.clone();
        res.mut_merge(other);
        res
    }

    pub fn mut_merge(&mut self, other: &Self) -> &mut Self {
        for (metric, entry) in other.measurements_index.iter() {
            let metric_measurements = self
                .measurements_index
                .entry(metric.clone())
                .or_insert_with(Default::default);
            let self_back_index = metric_measurements.back().map(|v| v.0);
            let other_back_index = entry.back().map(|v| v.0);
            match (self_back_index, other_back_index) {
                (Some(s), Some(o)) if s < o => {
                    let new_data = entry
                        .iter()
                        .rev()
                        .take_while(|(o, _)| s < *o)
                        .cloned()
                        .collect::<Vec<_>>();
                    metric_measurements.extend(new_data.iter().rev().cloned());
                }
                (None, Some(_)) => *metric_measurements = entry.clone(),
                _ => {}
            }
        }
        for (metric, entry) in other.measurements_timestamp.iter() {
            let metric_measurements = self
                .measurements_timestamp
                .entry(metric.clone())
                .or_insert_with(Default::default);
            let self_back_timestamp = metric_measurements.back().map(|v| v.0);
            let other_back_timestamp = entry.back().map(|v| v.0);
            match (self_back_timestamp, other_back_timestamp) {
                (Some(s), Some(o)) if s < o => {
                    let new_data = entry
                        .iter()
                        .rev()
                        .take_while(|(o, _)| s < *o)
                        .cloned()
                        .collect::<Vec<_>>();
                    metric_measurements.extend(new_data.iter().rev().cloned());
                }
                (None, Some(_)) => *metric_measurements = entry.clone(),
                _ => {}
            }
        }
        for (metric, entry) in other.evaluations_index.iter() {
            let task_evaluations = self
                .evaluations_index
                .entry(metric.clone())
                .or_insert_with(Default::default);
            let self_back_index = task_evaluations.back().map(|v| v.0);
            let other_back_index = entry.back().map(|v| v.0);
            match (self_back_index, other_back_index) {
                (Some(s), Some(o)) if s < o => {
                    let new_data = entry
                        .iter()
                        .rev()
                        .take_while(|(o, _)| s < *o)
                        .cloned()
                        .collect::<Vec<_>>();
                    task_evaluations.extend(new_data.iter().rev().cloned());
                }
                (None, Some(_)) => *task_evaluations = entry.clone(),
                _ => {}
            }
        }
        for (metric, entry) in other.evaluations_timestamp.iter() {
            let task_evaluations = self
                .evaluations_timestamp
                .entry(metric.clone())
                .or_insert_with(Default::default);
            let self_back_timestamp = task_evaluations.back().map(|v| v.0);
            let other_back_timestamp = entry.back().map(|v| v.0);
            match (self_back_timestamp, other_back_timestamp) {
                (Some(s), Some(o)) if s < o => {
                    let new_data = entry
                        .iter()
                        .rev()
                        .take_while(|(o, _)| s < *o)
                        .cloned()
                        .collect::<Vec<_>>();
                    task_evaluations.extend(new_data.iter().rev().cloned());
                }
                (None, Some(_)) => *task_evaluations = entry.clone(),
                _ => {}
            }
        }
        self.duration_index
            .extend(other.duration_index.iter().map(|(k, v)| (*k, *v)));
        self
    }

    pub fn to_table(&self) -> Table<Metrics, Tasks, Data> {
        let measurements_index = self
            .measurements_index
            .iter()
            .map(|(measurement, entries)| {
                let k = measurement.clone();
                let v = entries.iter().cloned().collect::<HashMap<_, _>>();
                (k, v)
            })
            .collect();
        let measurements_timestamp = self
            .measurements_timestamp
            .iter()
            .map(|(measurement, entries)| {
                let k = measurement.clone();
                let v = entries.iter().cloned().collect::<HashMap<_, _>>();
                (k, v)
            })
            .collect();
        let evaluations_index = self
            .evaluations_index
            .iter()
            .map(|(measurement, entries)| {
                let k = measurement.clone();
                let v = entries.iter().cloned().collect::<HashMap<_, _>>();
                (k, v)
            })
            .collect();
        let evaluations_timestamp = self
            .evaluations_timestamp
            .iter()
            .map(|(measurement, entries)| {
                let k = measurement.clone();
                let v = entries.iter().cloned().collect::<HashMap<_, _>>();
                (k, v)
            })
            .collect();
        Table {
            measurements_index,
            measurements_timestamp,
            evaluations_index,
            evaluations_timestamp,
            duration_index: self.duration_index.clone(),
        }
    }
}

pub use crate::command::nfdc::PacketStatistics;

#[cfg(test)]
mod tests {
    use crate::task::*;

    #[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
    enum Metrics {
        M1,
    }

    #[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
    enum Tasks {
        R1,
    }

    #[derive(Debug, PartialEq, Clone)]
    enum Data {
        M1(u64),
    }

    #[test]
    fn test_insert_mut_merge() {
        let mut log1: Logs<Metrics, Tasks, Data> = Logs::default();
        log1.insert_measurement(Measurement::new(Data::M1(0), 0), Metrics::M1);
        let m1 = Measurement::new(Data::M1(1), 1);
        log1.insert_measurement(m1.clone(), Metrics::M1);
        log1.insert_evaluation(Evaluation::new(true, 0), Tasks::R1);
        log1.insert_evaluation(Evaluation::new(true, 1), Tasks::R1);

        let mut log2: Logs<Metrics, Tasks, Data> = Logs::default();
        log2.insert_measurement(m1, Metrics::M1);
        log2.insert_measurement(Measurement::new(Data::M1(2), 2), Metrics::M1);
        log2.insert_measurement(Measurement::new(Data::M1(3), 3), Metrics::M1);
        log2.insert_evaluation(Evaluation::new(false, 2), Tasks::R1);
        log2.insert_evaluation(Evaluation::new(false, 3), Tasks::R1);

        println!("{:#?}", log1);
        println!("{:#?}", log2);

        log1.mut_merge(&log2);

        // println!("{:#?}", log1.merge(&log2));
        println!("{:#?}", log1);
        assert_eq!(log1.measurements_index[&Metrics::M1].len(), 4);
        assert_eq!(log1.measurements_timestamp[&Metrics::M1].len(), 4);
        assert_eq!(
            log1.measurements_index[&Metrics::M1]
                .iter()
                .map(|(i, _)| i)
                .cloned()
                .collect::<Vec<_>>(),
            [0, 1, 2, 3]
        );
    }
}
