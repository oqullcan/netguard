pub mod capture;
pub mod analysis;
pub mod cli;
pub mod ml;
pub mod reporting;
pub mod utils;
pub mod scan;

use anyhow::Result;
use cli::{App, Args};

/// Main NetGuard application
pub struct NetGuard {
    app: App,
}

impl NetGuard {
    /// Create a new NetGuard instance
    pub fn new() -> Self {
        Self {
            app: App::new(),
        }
    }
    
    /// Run the NetGuard application with the provided arguments
    pub fn run(&mut self, args: Args) -> Result<()> {
        self.app.run(args)
    }
} 