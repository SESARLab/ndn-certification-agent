use thiserror::Error as ThisError;

#[derive(Debug, ThisError)]
pub enum Error {
    #[error(transparent)]
    CommandError(#[from] crate::command::Error),
    #[error(transparent)]
    TimeoutError(#[from] async_std::future::TimeoutError),
}
