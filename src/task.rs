use crate::command;
use crate::task;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use futures::future::{TryFuture, TryJoinAll};
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
    pub evaluation: bool,
    pub index: u64,
    pub timestamp: DateTime<Utc>,
}

impl Evaluation {
    pub fn new(evaluation: bool, index: u64) -> Self {
        Self {
            evaluation,
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
    pub measurements_index: HashMap<Metrics, HashMap<u64, Data>>,
    pub measurements_timestamp: HashMap<Metrics, HashMap<DateTime<Utc>, Data>>,
    pub evaluations_index: HashMap<Tasks, HashMap<u64, bool>>,
    pub evaluations_timestamp: HashMap<Tasks, HashMap<DateTime<Utc>, bool>>,
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
        let entry = res
            .measurements_index
            .entry(metric.clone())
            .or_insert_with(HashMap::new);
        entry.insert(measurement.index, measurement.data.clone());
        let entry = res
            .measurements_timestamp
            .entry(metric)
            .or_insert_with(HashMap::new);
        entry.insert(measurement.timestamp, measurement.data);
        res
    }

    pub fn with_evaluation(
        &self,
        evaluation: Evaluation,
        task: Tasks,
    ) -> Logs<Metrics, Tasks, Data> {
        let mut res = self.clone();
        let entry = res
            .evaluations_index
            .entry(task.clone())
            .or_insert_with(HashMap::new);
        entry.insert(evaluation.index, evaluation.evaluation);
        let entry = res
            .evaluations_timestamp
            .entry(task)
            .or_insert_with(HashMap::new);
        entry.insert(evaluation.timestamp, evaluation.evaluation);
        res
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
        evaluations_index.extend(
            other
                .evaluations_index
                .iter()
                .map(|(k, v)| (k.clone(), v.clone())),
        );
        let mut evaluations_timestamp = self.evaluations_timestamp.clone();
        evaluations_timestamp.extend(
            other
                .evaluations_timestamp
                .iter()
                .map(|(k, v)| (k.clone(), v.clone())),
        );
        Self {
            measurements_index,
            measurements_timestamp,
            evaluations_index,
            evaluations_timestamp,
        }
    }
}

pub use crate::command::nfdc::PacketStatistics;
