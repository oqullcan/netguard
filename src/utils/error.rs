use std::io;
use thiserror::Error;

/// Custom result type for NetGuard
pub type Result<T> = std::result::Result<T, NetGuardError>;

/// Error types for NetGuard
#[derive(Error, Debug)]
pub enum NetGuardError {
    /// Errors related to network interfaces
    #[error("Interface error: {0}")]
    InterfaceError(String),
    
    /// Errors related to packet capture
    #[error("Capture error: {0}")]
    CaptureError(String),
    
    /// Errors related to protocol parsing
    #[error("Protocol error: {0}")]
    ProtocolError(String),
    
    /// Errors related to analysis
    #[error("Analysis error: {0}")]
    AnalysisError(String),
    
    /// Errors related to ML operations
    #[error("ML error: {0}")]
    MlError(String),
    
    /// Errors related to CLI
    #[error("CLI error: {0}")]
    CliError(String),
    
    /// Errors related to I/O operations
    #[error("I/O error: {0}")]
    IoError(io::Error),
    
    /// Errors related to configuration
    #[error("Configuration error: {0}")]
    ConfigError(String),
    
    /// Errors related to invalid port ranges
    #[error("Invalid port range: {0}")]
    InvalidPortRange(String),
    
    /// Errors related to reporting
    #[error("Reporting error: {0}")]
    ReportingError(String),
    
    /// Unknown errors
    #[error("Unknown error: {0}")]
    UnknownError(String),
}

impl NetGuardError {
    /// Create a new interface error
    pub fn interface_error<T: Into<String>>(message: T) -> Self {
        Self::InterfaceError(message.into())
    }
    
    /// Create a new capture error
    pub fn capture_error<T: Into<String>>(message: T) -> Self {
        Self::CaptureError(message.into())
    }
    
    /// Create a new protocol error
    pub fn protocol_error<T: Into<String>>(message: T) -> Self {
        Self::ProtocolError(message.into())
    }
    
    /// Create a new analysis error
    pub fn analysis_error<T: Into<String>>(message: T) -> Self {
        Self::AnalysisError(message.into())
    }
    
    /// Create a new ML error
    pub fn ml_error<T: Into<String>>(message: T) -> Self {
        Self::MlError(message.into())
    }
    
    /// Create a new CLI error
    pub fn cli_error<T: Into<String>>(message: T) -> Self {
        Self::CliError(message.into())
    }
    
    /// Create a new config error
    pub fn config_error<T: Into<String>>(message: T) -> Self {
        Self::ConfigError(message.into())
    }
    
    /// Create a new reporting error
    pub fn reporting_error<T: Into<String>>(message: T) -> Self {
        Self::ReportingError(message.into())
    }
}

// Allow conversion from pcap::Error to NetGuardError
impl From<pcap::Error> for NetGuardError {
    fn from(error: pcap::Error) -> Self {
        Self::CaptureError(error.to_string())
    }
}

// Allow conversion from serde_json::Error to NetGuardError
impl From<serde_json::Error> for NetGuardError {
    fn from(error: serde_json::Error) -> Self {
        Self::ConfigError(format!("JSON error: {}", error))
    }
}

// Allow conversion from std::num::ParseIntError to NetGuardError
impl From<std::num::ParseIntError> for NetGuardError {
    fn from(error: std::num::ParseIntError) -> Self {
        Self::ConfigError(format!("Parse error: {}", error))
    }
}

// Allow conversion from anyhow::Error to NetGuardError
impl From<anyhow::Error> for NetGuardError {
    fn from(error: anyhow::Error) -> Self {
        Self::UnknownError(error.to_string())
    }
}

// Allow conversion from std::io::Error to NetGuardError
impl From<std::io::Error> for NetGuardError {
    fn from(error: std::io::Error) -> Self {
        Self::IoError(error)
    }
} 