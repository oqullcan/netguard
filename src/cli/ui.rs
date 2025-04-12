use anyhow::{Result, Context};
use std::io::{self, Write};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::{Duration, Instant};
use colored::*;

use crate::analysis::{AnalysisService, Threat};
use crate::capture::{CaptureService, Packet};
use crate::cli::Args;
use crate::cli::args::Command;

/// Handles user interaction and display
pub struct UserInterface {
    packet_count: u64,
    threat_count: u64,
    start_time: Option<Instant>,
}

impl UserInterface {
    /// Create a new user interface
    pub fn new() -> Self {
        Self {
            packet_count: 0,
            threat_count: 0,
            start_time: None,
        }
    }
    
    /// Start the user interface
    pub fn start(&mut self, args: Args) -> Result<()> {
        match &args.command {
            Some(Command::Interfaces) => {
                // List network interfaces
                let interfaces = CaptureService::list_interfaces()?;
                self.display_interfaces(&interfaces);
            },
            Some(Command::Scan(scan_args)) => {
                // Run a network scan
                self.run_scan(scan_args, args.verbose)?;
            },
            Some(Command::Analyze(analyze_args)) => {
                // Analyze a packet capture file
                self.analyze_file(&analyze_args.file, analyze_args.deep, args.verbose)?;
            },
            None => {
                // Run real-time packet capture and analysis
                self.run_capture(args)?;
            },
        }
        
        Ok(())
    }
    
    /// Run the packet capture and analysis
    fn run_capture(&mut self, args: Args) -> Result<()> {
        // Default to the first interface if none specified
        let interface_name = match args.interface.as_deref() {
            Some(name) => name.to_string(),
            None => {
                let interfaces = CaptureService::list_interfaces()?;
                self.display_interfaces(&interfaces);
                
                if interfaces.is_empty() {
                    anyhow::bail!("No network interfaces found");
                }
                
                print!("Select interface [1-{}]: ", interfaces.len());
                io::stdout().flush()?;
                
                let mut input = String::new();
                io::stdin().read_line(&mut input)?;
                
                let index = input.trim().parse::<usize>().context("Invalid interface number")? - 1;
                if index >= interfaces.len() {
                    anyhow::bail!("Invalid interface selection");
                }
                
                interfaces[index].name.clone()
            }
        };
        
        println!("{} {}", "Starting packet capture on interface:".green(), interface_name.bold());
        
        if args.use_ml {
            println!("{}", "Machine learning detection: ENABLED".green());
        } else {
            println!("{}", "Machine learning detection: DISABLED".yellow());
        }
        
        // Set up channels
        let (packet_tx, packet_rx) = mpsc::channel::<Packet>();
        let (packet_count_tx, packet_count_rx) = mpsc::channel::<Packet>(); // New channel for packet counting
        let (threat_tx, threat_rx) = mpsc::channel::<Threat>();
        
        // Create services
        let mut capture_service = CaptureService::new(&interface_name)?;
        let mut analysis_service = AnalysisService::new();
        
        // Set filter if provided
        if let Some(filter) = args.filter {
            capture_service.set_filter(&filter)?;
        }
        
        // Configure analysis service
        if args.use_ml {
            analysis_service.enable_ml_detection(true);
        }
        
        // Start a thread to count packets
        let packet_counter_thread = thread::spawn(move || {
            let mut count = 0;
            
            for packet in packet_count_rx {
                // Count the packet
                count += 1;
                
                // Forward to analysis service
                if packet_tx.send(packet).is_err() {
                    break;
                }
            }
            
            count
        });
        
        // Start the services
        capture_service.start(packet_count_tx)?;
        analysis_service.start(packet_rx, threat_tx)?;
        
        // Record start time
        self.start_time = Some(Instant::now());
        
        // Run the display loop
        self.run_display_loop(threat_rx, args.verbose, args.timeout)?;
        
        // Stop services
        capture_service.stop()?;
        analysis_service.stop()?;
        
        // Get final packet count
        if let Ok(count) = packet_counter_thread.join() {
            self.packet_count = count;
        }
        
        // Display summary
        self.print_summary();
        
        Ok(())
    }
    
    /// Run a network scan
    pub fn run_scan(&mut self, scan_args: &crate::cli::args::ScanArgs, verbose: bool) -> Result<()> {
        println!("{} {}", "Scanning target:".green(), scan_args.target.bold());
        
        if let Some(port_range) = &scan_args.port_range {
            println!("{} {}", "Port range:".green(), port_range.bold());
        }
        
        println!("{} {}", "Scan intensity:".green(), scan_args.intensity.to_string().bold());
        
        // Parse port range
        let port_range = if let Some(range_str) = &scan_args.port_range {
            let parts: Vec<&str> = range_str.split('-').collect();
            if parts.len() == 2 {
                if let (Ok(start), Ok(end)) = (parts[0].parse::<u16>(), parts[1].parse::<u16>()) {
                    Some((start, end))
                } else {
                    return Err(anyhow::anyhow!("Invalid port range format: {}", range_str));
                }
            } else {
                return Err(anyhow::anyhow!("Invalid port range format: {}", range_str));
            }
        } else {
            // Default to common ports if not specified
            Some((1, 1024))
        };
        
        if let Some((start_port, end_port)) = port_range {
            use crate::scan::{Scanner, ScanType};
            
            // Create a scanner based on the selected intensity
            let scanner = match scan_args.intensity {
                1 => Scanner::new(scan_args.target.clone(), ScanType::Basic),
                2 => Scanner::new(scan_args.target.clone(), ScanType::Quick),
                3 => Scanner::new(scan_args.target.clone(), ScanType::Default),
                4 => Scanner::new(scan_args.target.clone(), ScanType::Aggressive),
                5 => Scanner::new(scan_args.target.clone(), ScanType::Comprehensive),
                _ => return Err(anyhow::anyhow!("Invalid scan intensity: {}", scan_args.intensity)),
            };
            
            // Start the scan
            println!("Starting scan of {} ports ({}-{})", end_port - start_port + 1, start_port, end_port);
            let results = scanner.scan_ports(start_port, end_port)?;
            
            // Display results
            println!("\nScan Results:");
            println!("--------------------------------------------------------------------------------");
            
            let mut open_ports = 0;
            for result in &results {
                if result.is_open {
                    open_ports += 1;
                    let service = if let Some(service) = &result.service {
                        service.as_str()
                    } else {
                        "unknown"
                    };
                    
                    println!("Port {:5} ({:6}) - OPEN   - {}", 
                        result.port, 
                        result.protocol.to_string().to_lowercase(),
                        service
                    );
                    
                    // Display vulnerabilities if any
                    if !result.vulnerabilities.is_empty() {
                        for vuln in &result.vulnerabilities {
                            println!("  - [{}] {}", vuln.severity, vuln.description);
                        }
                    }
                } else if verbose {
                    // Show closed ports only in verbose mode
                    println!("Port {:5} ({:6}) - CLOSED", 
                        result.port, 
                        result.protocol.to_string().to_lowercase()
                    );
                }
            }
            
            println!("--------------------------------------------------------------------------------");
            println!("Scan complete: {} ports scanned, {} open ports found.", 
                end_port - start_port + 1,
                open_ports
            );
        } else {
            return Err(anyhow::anyhow!("Failed to parse port range"));
        }
        
        Ok(())
    }
    
    /// Analyze a packet capture file
    fn analyze_file(&mut self, file_path: &str, deep: bool, verbose: bool) -> Result<()> {
        println!("{} {}", "Analyzing packet capture file:".green(), file_path.bold());
        
        if deep {
            println!("{}", "Deep packet inspection: ENABLED".green());
        } else {
            println!("{}", "Deep packet inspection: DISABLED".yellow());
        }
        
        // Open the PCAP file
        let cap = match pcap::Capture::from_file(file_path) {
            Ok(cap) => cap,
            Err(e) => {
                return Err(anyhow::anyhow!("Failed to open PCAP file: {}", e));
            }
        };
        
        // Set up analysis service
        let mut analysis_service = crate::analysis::AnalysisService::new();
        
        // Enable ML if deep inspection is requested
        if deep {
            analysis_service.enable_ml_detection(true);
        }
        
        // Set up channels for analysis
        let (packet_tx, packet_rx) = mpsc::channel();
        let (threat_tx, threat_rx) = mpsc::channel();
        
        // Start analysis service
        analysis_service.start(packet_rx, threat_tx)?;
        
        // Start a thread to read packets from the file
        let file_reader_thread = thread::spawn(move || {
            let mut count = 0;
            let mut cap = cap;
            
            while let Ok(packet_data) = cap.next_packet() {
                if let Some(packet) = crate::capture::Packet::from_pcap_packet(&packet_data) {
                    count += 1;
                    if packet_tx.send(packet).is_err() {
                        break;
                    }
                }
            }
            
            count
        });
        
        // Record start time
        self.start_time = Some(Instant::now());
        
        // Start display loop with a short timeout to show initial results
        let display_timeout = 5; // 5 seconds to show initial results
        self.run_display_loop(threat_rx, verbose, display_timeout)?;
        
        // Wait for file reading to complete
        if let Ok(count) = file_reader_thread.join() {
            self.packet_count = count;
        }
        
        // Stop analysis service
        analysis_service.stop()?;
        
        // Print summary
        self.print_summary();
        
        Ok(())
    }
    
    /// Run the display loop for threats and user interaction
    fn run_display_loop(&mut self, threat_rx: Receiver<Threat>, _verbose: bool, timeout: u64) -> Result<()> {
        let start_time = Instant::now();
        let timeout_duration = if timeout > 0 {
            Some(Duration::from_secs(timeout))
        } else {
            None
        };
        
        println!("{}", "\nMonitoring traffic...".green());
        println!("{}", "(Press Ctrl+C or 'q' to stop)".dimmed());
        println!("{}", "-".repeat(80).dimmed());
        
        // Set up terminal for non-blocking input
        let _input = String::new();
        
        loop {
            // Check for timeout
            if let Some(duration) = timeout_duration {
                if start_time.elapsed() >= duration {
                    println!("{}", "\nCapture timeout reached.".yellow());
                    break;
                }
            }
            
            // Check for user input (non-blocking)
            if let Ok(Some(key)) = self.check_user_input() {
                if key == 'q' || key == 'Q' {
                    println!("{}", "\nCapture stopped by user.".yellow());
                    break;
                }
            }
            
            // Check for threats
            match threat_rx.try_recv() {
                Ok(threat) => {
                    self.threat_count += 1;
                    self.display_threat(&threat);
                },
                Err(mpsc::TryRecvError::Empty) => {
                    // No threats available, wait a bit
                    thread::sleep(Duration::from_millis(100));
                },
                Err(mpsc::TryRecvError::Disconnected) => {
                    // Channel closed, stop the loop
                    break;
                }
            }
        }
        
        Ok(())
    }
    
    /// Check for user input (non-blocking)
    fn check_user_input(&self) -> Result<Option<char>> {
        // This is a simplified implementation
        // A real implementation would use crossterm or similar for non-blocking input
        
        // For demo purposes, we'll just return None
        Ok(None)
    }
    
    /// Display a list of available network interfaces
    fn display_interfaces(&self, interfaces: &[crate::capture::DeviceInfo]) {
        println!("\n{}", "Available Network Interfaces:".bold().green());
        println!("{}", "-".repeat(80).dimmed());
        
        for (i, interface) in interfaces.iter().enumerate() {
            println!(
                " {}. {}",
                (i + 1).to_string().cyan(),
                interface.name.bold()
            );
            
            if let Some(desc) = &interface.description {
                println!("    {}", desc.dimmed());
            }
        }
        
        println!("{}\n", "-".repeat(80).dimmed());
    }
    
    /// Display a detected threat
    fn display_threat(&self, threat: &Threat) {
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
    
    /// Print a summary of the capture
    fn print_summary(&self) {
        if let Some(start_time) = self.start_time {
            let duration = start_time.elapsed();
            let minutes = duration.as_secs() / 60;
            let seconds = duration.as_secs() % 60;
            
            println!("\n{}", "Capture Summary".bold().green());
            println!("{}", "-".repeat(80).dimmed());
            println!("Duration: {} minute(s), {} second(s)", minutes, seconds);
            println!("Packets processed: {}", self.packet_count);
            println!("Threats detected: {}", self.threat_count);
            println!("{}", "-".repeat(80).dimmed());
        }
    }
} 