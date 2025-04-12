pub mod config;
pub mod logger;
pub mod error;

pub use config::Config;
pub use logger::{setup_logger, LogLevel};
pub use error::{NetGuardError, Result};

use std::time::{Duration, Instant};

/// Format a duration as human readable (e.g., "2h 15m 30s")
pub fn format_duration(duration: Duration) -> String {
    let seconds = duration.as_secs();
    
    if seconds < 60 {
        return format!("{}s", seconds);
    }
    
    let minutes = seconds / 60;
    let seconds_remainder = seconds % 60;
    
    if minutes < 60 {
        return format!("{}m {}s", minutes, seconds_remainder);
    }
    
    let hours = minutes / 60;
    let minutes_remainder = minutes % 60;
    
    format!("{}h {}m {}s", hours, minutes_remainder, seconds_remainder)
}

/// Format a timestamp as human readable
pub fn format_timestamp(timestamp: Instant) -> String {
    let duration = timestamp.elapsed();
    format_duration(duration)
}

/// Format a byte size as human readable (e.g., "1.5 MB")
pub fn format_size(bytes: usize) -> String {
    const KB: usize = 1024;
    const MB: usize = KB * 1024;
    const GB: usize = MB * 1024;
    
    if bytes < KB {
        return format!("{} B", bytes);
    } else if bytes < MB {
        return format!("{:.1} KB", bytes as f64 / KB as f64);
    } else if bytes < GB {
        return format!("{:.1} MB", bytes as f64 / MB as f64);
    } else {
        return format!("{:.1} GB", bytes as f64 / GB as f64);
    }
}

/// Check if a string represents a valid IP address
pub fn is_valid_ip(ip: &str) -> bool {
    ip.parse::<std::net::IpAddr>().is_ok()
}

/// Check if a string represents a valid network interface name
pub fn is_valid_interface(interface: &str) -> bool {
    // This is a simplified check - in a real implementation, you would check
    // if this interface exists on the system
    !interface.is_empty() && !interface.contains(char::is_whitespace)
}

/// Parse a port range string (e.g., "80-443")
pub fn parse_port_range(range: &str) -> Result<(u16, u16)> {
    if range.contains('-') {
        let parts: Vec<&str> = range.split('-').collect();
        if parts.len() == 2 {
            let start = parts[0].trim().parse::<u16>()
                .map_err(|_| NetGuardError::InvalidPortRange("Invalid start port".to_string()))?;
                
            let end = parts[1].trim().parse::<u16>()
                .map_err(|_| NetGuardError::InvalidPortRange("Invalid end port".to_string()))?;
                
            if start <= end {
                return Ok((start, end));
            }
        }
    } else {
        // Single port
        let port = range.trim().parse::<u16>()
            .map_err(|_| NetGuardError::InvalidPortRange("Invalid port number".to_string()))?;
        return Ok((port, port));
    }
    
    Err(NetGuardError::InvalidPortRange(format!("Invalid port range: {}", range)))
} 