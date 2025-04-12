use clap::{Args as ClapArgs, Parser, Subcommand};

/// Command-line arguments for the NetGuard application
#[derive(Debug, Parser)]
#[clap(name = "netguard")]
#[clap(about = "High-performance network security analysis tool")]
pub struct Args {
    /// Subcommands
    #[clap(subcommand)]
    pub command: Option<Command>,
    
    /// Network interface to monitor
    #[clap(short, long, value_name = "INTERFACE")]
    pub interface: Option<String>,
    
    /// Enable verbose logging
    #[clap(short, long)]
    pub verbose: bool,
    
    /// Enable machine learning detection
    #[clap(long = "ml-detection")]
    pub use_ml: bool,
    
    /// Timeout in seconds (0 for no timeout)
    #[clap(short, long, default_value = "0")]
    pub timeout: u64,
    
    /// Path to save the capture file
    #[clap(long, value_name = "FILE")]
    pub output: Option<String>,
    
    /// Filter string in pcap format
    #[clap(short = 'f', long, value_name = "FILTER")]
    pub filter: Option<String>,
}

/// Subcommands for the NetGuard application
#[derive(Debug, Subcommand)]
pub enum Command {
    /// List available network interfaces
    #[clap(name = "interfaces")]
    Interfaces,
    
    /// Scan a target for security vulnerabilities
    #[clap(name = "scan")]
    Scan(ScanArgs),
    
    /// Analyze a captured packet file
    #[clap(name = "analyze")]
    Analyze(AnalyzeArgs),
}

/// Arguments for the scan subcommand
#[derive(Debug, ClapArgs)]
pub struct ScanArgs {
    /// IP address or hostname to scan
    #[clap(required = true)]
    pub target: String,
    
    /// Port range to scan (e.g., 1-1000)
    #[clap(short, long, value_name = "RANGE")]
    pub port_range: Option<String>,
    
    /// Scan intensity (1-5)
    #[clap(short, long, default_value = "3")]
    pub intensity: u8,
}

/// Arguments for the analyze subcommand
#[derive(Debug, ClapArgs)]
pub struct AnalyzeArgs {
    /// Path to the packet capture file
    #[clap(required = true)]
    pub file: String,
    
    /// Enable deep packet inspection
    #[clap(short, long)]
    pub deep: bool,
}

/// Parse command-line arguments
pub fn parse_args() -> Args {
    Args::parse()
} 