pub mod args;
mod ui;

pub use args::{Args, parse_args};
pub use ui::UserInterface;

use colored::*;
use anyhow::Result;

use crate::analysis::Threat;
use crate::capture::{Packet, DeviceInfo};

/// Main CLI app that handles user interaction
pub struct App {
    ui: UserInterface,
}

impl App {
    /// Create a new CLI application
    pub fn new() -> Self {
        Self {
            ui: UserInterface::new(),
        }
    }
    
    /// Run the application
    pub fn run(&mut self, args: Args) -> Result<()> {
        // Display welcome message
        self.print_welcome();
        
        // Start the UI
        self.ui.start(args)?;
        
        Ok(())
    }
    
    /// Print welcome message
    fn print_welcome(&self) {
        println!("{}", "\n  _   _      _    ____                     _ _             ".bright_cyan());
        println!("{}", " | \\ | | ___| |_ / ___| _   _  __ _ _ __ __| (_) __ _ _ __  ".bright_cyan());
        println!("{}", " |  \\| |/ _ \\ __| |  _ | | | |/ _` | '__/ _` | |/ _` | '_ \\ ".bright_cyan());
        println!("{}", " | |\\  |  __/ |_| |_| || |_| | (_| | | | (_| | | (_| | | | |".bright_cyan());
        println!("{}", " |_| \\_|\\___|\\__|\\____|\\__,_|\\__,_|_|  \\__,_|_|\\__,_|_| |_|".bright_cyan());
        println!("{}", "                                                             ".bright_cyan());
        println!("{}", " Network Security Analysis Tool                              ".bright_cyan());
        println!("{}", " Version 0.1.0                                              \n".bright_cyan());
    }
    
    /// Display a list of network interfaces
    pub fn display_interfaces(&self, interfaces: &[DeviceInfo]) {
        println!("\n{}", "Available Network Interfaces:".bold().green());
        println!("{}", "-".repeat(80).dimmed());
        
        for (i, interface) in interfaces.iter().enumerate() {
            let interface_type = if interface.is_loopback {
                "Loopback".yellow()
            } else {
                "Network".green()
            };
            
            println!(
                " {}. {} ({})",
                (i + 1).to_string().cyan(),
                interface.name.bold(),
                interface_type
            );
            
            if let Some(desc) = &interface.description {
                println!("    {}", desc.dimmed());
            }
        }
        
        println!("{}\n", "-".repeat(80).dimmed());
    }
    
    /// Display a captured packet
    pub fn display_packet(&self, packet: &Packet) {
        println!("{}", packet.summary());
    }
    
    /// Display a detected threat
    pub fn display_threat(&self, threat: &Threat) {
        let severity_color = match threat.severity {
            1..=3 => "blue".to_string(),
            4..=6 => "yellow".to_string(),
            7..=8 => "red".to_string(),
            9..=10 => "bright_red".to_string(),
            _ => "white".to_string(),
        };
        
        println!(
            "{} [Severity: {}] {}",
            "THREAT DETECTED:".bold().red(),
            threat.severity.to_string().color(severity_color),
            threat.description.bold()
        );
        
        println!(
            "  Packet: {} -> {}",
            threat.associated_packet.source_ip.map(|ip| ip.to_string()).unwrap_or_else(|| "unknown".to_string()),
            threat.associated_packet.dest_ip.map(|ip| ip.to_string()).unwrap_or_else(|| "unknown".to_string())
        );
        
        println!("{}", "-".repeat(80).dimmed());
    }
} 