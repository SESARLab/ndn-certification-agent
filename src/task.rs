use crate::command;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::hash::Hash;
use thiserror::Error as ThisError;

#[derive(Debug, ThisError)]
pub enum Error {
    /// Command error
    #[error(transparent)]
    CommandError(#[from] command::Error),

    /// Error during task execution
    #[error("{0}")]
    EvaluationError(String),
}

/// Metric task
#[async_trait]
pub trait Metric<Measure, Data> {
    async fn eval() -> Result<Measurement<Data>, Error>;
}

/// Output of a metric evaluation
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Measurement<Data> {
    data: Data,
    time_index: u64,
    timestamp: DateTime<Utc>,
}

/// Evaluable task
///
/// Represents a constraint or a rule evaluation task
#[async_trait]
pub trait Evaluable<Measure, Task, Data, Dependencies>
where
    Measure: Hash + Eq,
    Task: Hash + Eq,
{
    async fn eval() -> Result<Output<Measure, Task, Data>, Error>;
}

/// Task evaluation output
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Output<Measure, Task, Data>
where
    Measure: Hash + Eq,
    Task: Hash + Eq,
{
    output: bool,
    measurements: HashMap<Measure, Measurement<Data>>,
    partial_results: HashMap<Task, bool>,
}
