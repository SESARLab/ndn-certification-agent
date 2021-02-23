//! Metrics module

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Measurement<M> {
    timestamp: DateTime<Utc>,
    data: M,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Metric<M> {
    name: String,
    measurements: VecDeque<Measurement<M>>,
}
