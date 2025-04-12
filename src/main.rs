use std::process;
use anyhow::Result;

use netguard::NetGuard;
use netguard::cli::parse_args;

/// Main entry point for the NetGuard application
fn main() -> Result<()> {
    // Parse command line arguments
    let args = parse_args();
    
    // Initialize the NetGuard application
    let mut app = NetGuard::new();
    
    // Run the application
    if let Err(e) = app.run(args) {
        eprintln!("Error: {}", e);
        process::exit(1);
    }
    
    Ok(())
}
