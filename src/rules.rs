use async_trait::async_trait;
use futures::future::TryFuture;
use std::error::Error;
use crate::metrics::Measurement;

pub async fn constraint<M, D, E>(dependencies: D, evaluation: E) -> Result<bool, Box<dyn Error>>
where
    D: TryFuture<Output = Result<Measurement<M>, Box<dyn Error>>>,
    E: Fn(Measurement<M>) -> bool,
{
    let measurements = dependencies.await?;
    Ok(evaluation(measurements))
}

pub async fn rule<D, E>(dependencies: D, evaluation: E) -> Result<bool, Box<dyn Error>>
where
  D: TryFuture<Output = Result<Measurement<bool>, Box<dyn Error>>>,
  E: Fn(Measurement<bool>) -> bool,
{
	let measurements = dependencies.await?;
	Ok(evaluation(measurements))
}

