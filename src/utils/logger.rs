use anyhow::{Context, Result};
use env_logger::Builder;
use log::LevelFilter;
use std::fs::File;
use std::io::Write;
use std::path::Path;

/// Log level for application
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    /// Only errors are logged
    Error,
    
    /// Warnings and errors are logged
    Warn,
    
    /// Info, warnings, and errors are logged
    Info,
    
    /// Debug, info, warnings, and errors are logged
    Debug,
    
    /// All messages including trace are logged
    Trace,
}

impl LogLevel {
    /// Convert to LevelFilter
    pub fn to_level_filter(&self) -> LevelFilter {
        match self {
            LogLevel::Error => LevelFilter::Error,
            LogLevel::Warn => LevelFilter::Warn,
            LogLevel::Info => LevelFilter::Info,
            LogLevel::Debug => LevelFilter::Debug,
            LogLevel::Trace => LevelFilter::Trace,
        }
    }
    
    /// Parse from string
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "error" => LogLevel::Error,
            "warn" | "warning" => LogLevel::Warn,
            "info" => LogLevel::Info,
            "debug" => LogLevel::Debug,
            "trace" => LogLevel::Trace,
            _ => LogLevel::Info, // Default to info level
        }
    }
}

/// Set up the application logger
pub fn setup_logger(level: LogLevel, log_file: Option<&Path>) -> Result<()> {
    let mut builder = Builder::new();
    
    // Set global log level
    builder.filter_level(level.to_level_filter());
    
    // Configure formatting
    builder.format(|buf, record| {
        let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S%.3f");
        
        writeln!(
            buf,
            "[{}] {} [{}] {}",
            timestamp,
            record.level(),
            record.target(),
            record.args()
        )
    });
    
    // Configure output destination(s)
    if let Some(path) = log_file {
        let file = File::create(path)
            .with_context(|| format!("Failed to create log file: {}", path.display()))?;
            
        builder.target(env_logger::Target::Pipe(Box::new(file)));
    } else {
        builder.target(env_logger::Target::Stdout);
    }
    
    // Initialize the logger
    builder.init();
    
    log::info!("Logger initialized at level: {:?}", level);
    
    Ok(())
}

/// A utility struct for log rotation
pub struct LogRotator {
    /// Base path for log files
    base_path: std::path::PathBuf,
    
    /// Maximum number of log files to keep
    max_logs: usize,
    
    /// Maximum size of log file before rotation
    max_size: u64,
}

impl LogRotator {
    /// Create a new log rotator
    pub fn new(base_path: std::path::PathBuf, max_logs: usize, max_size: u64) -> Self {
        Self {
            base_path,
            max_logs,
            max_size,
        }
    }
    
    /// Rotate logs if necessary
    pub fn rotate_if_needed(&self) -> Result<std::path::PathBuf> {
        let current_log_path = self.current_log_path();
        
        // Check if we need to rotate
        if self.needs_rotation(&current_log_path)? {
            self.rotate()?;
        }
        
        Ok(current_log_path)
    }
    
    /// Check if rotation is needed
    fn needs_rotation(&self, path: &Path) -> Result<bool> {
        if !path.exists() {
            return Ok(false);
        }
        
        let metadata = std::fs::metadata(path)
            .with_context(|| format!("Failed to get metadata for log file: {}", path.display()))?;
            
        Ok(metadata.len() >= self.max_size)
    }
    
    /// Get path to current log file
    fn current_log_path(&self) -> std::path::PathBuf {
        self.base_path.join("netguard.log")
    }
    
    /// Rotate log files
    fn rotate(&self) -> Result<()> {
        // Check if directory exists, create if not
        if let Some(parent) = self.base_path.parent() {
            if !parent.exists() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("Failed to create log directory: {}", parent.display()))?;
            }
        }
        
        // Shift existing log files
        for i in (1..self.max_logs).rev() {
            let old_path = self.base_path.join(format!("netguard.{}.log", i));
            let new_path = self.base_path.join(format!("netguard.{}.log", i + 1));
            
            if old_path.exists() {
                std::fs::rename(&old_path, &new_path)
                    .with_context(|| format!("Failed to rename log file from {} to {}", old_path.display(), new_path.display()))?;
            }
        }
        
        // Rename current log to .1
        let current = self.current_log_path();
        let new_path = self.base_path.join("netguard.1.log");
        
        if current.exists() {
            std::fs::rename(&current, &new_path)
                .with_context(|| format!("Failed to rename current log file to {}", new_path.display()))?;
        }
        
        // Delete any logs beyond max_logs
        let max_log_path = self.base_path.join(format!("netguard.{}.log", self.max_logs + 1));
        if max_log_path.exists() {
            std::fs::remove_file(&max_log_path)
                .with_context(|| format!("Failed to delete old log file: {}", max_log_path.display()))?;
        }
        
        Ok(())
    }
} 