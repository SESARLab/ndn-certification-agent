use crate::command;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
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
    pub measurements_index: HashMap<(Metrics, u64), Data>,
    pub measurements_timestamp: HashMap<(Metrics, DateTime<Utc>), Data>,
    pub evaluations_index: HashMap<(Tasks, u64), bool>,
    pub evaluations_timestamp: HashMap<(Tasks, DateTime<Utc>), bool>,
    pub duration_index: HashMap<u64, i64>,
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

impl<Metrics, Tasks, Data> Default for Logs<Metrics, Tasks, Data>
where
    Metrics: Hash + Eq,
    Tasks: Hash + Eq,
{
    fn default() -> Self {
        Logs {
            measurements_index: Default::default(),
            measurements_timestamp: Default::default(),
            evaluations_index: Default::default(),
            evaluations_timestamp: Default::default(),
            duration_index: Default::default(),
        }
    }
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
        res.measurements_index.insert(
            (metric.clone(), measurement.index),
            measurement.data.clone(),
        );
        res.measurements_timestamp
            .insert((metric, measurement.timestamp), measurement.data);
        res
    }

    pub fn insert_measurement(
        &mut self,
        measurement: Measurement<Data>,
        metric: Metrics,
    ) -> &mut Self {
        self.measurements_index.insert(
            (metric.clone(), measurement.index),
            measurement.data.clone(),
        );
        self.measurements_timestamp
            .insert((metric, measurement.timestamp), measurement.data);
        self
    }

    pub fn with_evaluation(
        &self,
        evaluation: Evaluation,
        task: Tasks,
    ) -> Logs<Metrics, Tasks, Data> {
        let mut res = self.clone();
        res.evaluations_index
            .insert((task.clone(), evaluation.index), evaluation.value);
        res.evaluations_timestamp
            .insert((task, evaluation.timestamp), evaluation.value);
        res
    }

    pub fn insert_evaluation(&mut self, evaluation: Evaluation, task: Tasks) -> &mut Self {
        self.evaluations_index
            .insert((task.clone(), evaluation.index), evaluation.value);
        self.evaluations_timestamp
            .insert((task, evaluation.timestamp), evaluation.value);
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
        let mut measurements_index = self.measurements_index.clone();
        measurements_index.extend(
            other
                .measurements_index
                .iter()
                .map(|(k, v)| (k.clone(), v.clone())),
        );
        let mut measurements_timestamp = self.measurements_timestamp.clone();
        measurements_timestamp.extend(
            other
                .measurements_timestamp
                .iter()
                .map(|(k, v)| (k.clone(), v.clone())),
        );
        let mut evaluations_index = self.evaluations_index.clone();
        evaluations_index.extend(other.evaluations_index.iter().map(|(k, v)| (k.clone(), *v)));
        let mut evaluations_timestamp = self.evaluations_timestamp.clone();
        evaluations_timestamp.extend(
            other
                .evaluations_timestamp
                .iter()
                .map(|(k, v)| (k.clone(), *v)),
        );
        let mut duration_index = self.duration_index.clone();
        duration_index.extend(other.duration_index.iter().map(|(k, v)| (*k, *v)));

        Self {
            measurements_index,
            measurements_timestamp,
            evaluations_index,
            evaluations_timestamp,
            duration_index,
        }
    }

    pub fn mut_merge(&mut self, other: &Self) -> &mut Self {
        self.measurements_index.extend(
            other
                .measurements_index
                .iter()
                .map(|(k, v)| (k.clone(), v.clone())),
        );
        self.measurements_timestamp.extend(
            other
                .measurements_timestamp
                .iter()
                .map(|(k, v)| (k.clone(), v.clone())),
        );
        self.evaluations_index
            .extend(other.evaluations_index.iter().map(|(k, v)| (k.clone(), *v)));
        self.evaluations_timestamp.extend(
            other
                .evaluations_timestamp
                .iter()
                .map(|(k, v)| (k.clone(), *v)),
        );
        self.duration_index
            .extend(other.duration_index.iter().map(|(k, v)| (*k, *v)));
        self
    }

    pub fn to_table(&self) -> Table<Metrics, Tasks, Data> {
        let measurements_index = self.measurements_index.iter().fold(
            HashMap::new(),
            |mut acc, ((measurement, index), data)| {
                let entry = acc.entry(measurement.clone()).or_insert_with(HashMap::new);
                entry.insert(*index, data.clone());
                acc
            },
        );

        let measurements_timestamp = self.measurements_timestamp.iter().fold(
            HashMap::new(),
            |mut acc, ((measurement, timestamp), data)| {
                let entry = acc.entry(measurement.clone()).or_insert_with(HashMap::new);
                entry.insert(*timestamp, data.clone());
                acc
            },
        );

        let evaluations_index = self.evaluations_index.iter().fold(
            HashMap::new(),
            |mut acc, ((task, index), value)| {
                let entry = acc.entry(task.clone()).or_insert_with(HashMap::new);
                entry.insert(*index, *value);
                acc
            },
        );

        let evaluations_timestamp = self.evaluations_timestamp.iter().fold(
            HashMap::new(),
            |mut acc, ((task, timestamp), value)| {
                let entry = acc.entry(task.clone()).or_insert_with(HashMap::new);
                entry.insert(*timestamp, *value);
                acc
            },
        );

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
