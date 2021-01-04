use thiserror::Error as ThisError;

#[derive(Debug, ThisError)]
pub enum Error {
  #[error(transparent)]
	ClientError(#[from] crate::client::Error),
	#[error(transparent)]
	TimeoutError(#[from] async_std::future::TimeoutError)
}
