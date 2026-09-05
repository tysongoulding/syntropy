use thiserror::Error;

#[derive(Error, Debug)]
pub enum TunnelError {
    #[error("Transport error: {0}")]
    Transport(#[from] tonic::transport::Error),

    #[error("gRPC error: {0}")]
    Status(#[from] Box<tonic::Status>),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Channel send error: {0}")]
    Send(String),

    #[error("Connection closed")]
    ConnectionClosed,

    #[error("Connection timed out after {0:?}")]
    Timeout(std::time::Duration),

    #[error("Max reconnect attempts ({0}) exceeded")]
    MaxReconnectAttemptsExceeded(usize),

    #[error("Authentication error: {0}")]
    Authentication(String),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Internal error: {0}")]
    Internal(String),
}

impl From<tonic::Status> for TunnelError {
    fn from(status: tonic::Status) -> Self {
        Self::Status(Box::new(status))
    }
}

pub type Result<T> = std::result::Result<T, TunnelError>;
