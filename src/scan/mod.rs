//! Port scanning and service detection functionality

use std::collections::HashMap;
use std::net::TcpStream;
use std::net::IpAddr;
use std::str::FromStr;
use std::time::Duration;
use anyhow::Result;
use std::io::{Read, Write};
use std::thread;

/// Scan result for a single port
#[derive(Debug, Clone)]
pub struct ScanResult {
    /// The port number
    pub port: u16,
    
    /// Whether the port is open
    pub is_open: bool,
    
    /// Protocol detected on the port
    pub protocol: Protocol,
    
    /// Service name if detected
    pub service: Option<String>,
    
    /// List of potential vulnerabilities detected
    pub vulnerabilities: Vec<Vulnerability>,
}

/// Protocol types
#[derive(Debug, Clone, PartialEq)]
pub enum Protocol {
    /// TCP protocol
    TCP,
    
    /// UDP protocol
    UDP,
}

impl ToString for Protocol {
    fn to_string(&self) -> String {
        match self {
            Protocol::TCP => "TCP".to_string(),
            Protocol::UDP => "UDP".to_string(),
        }
    }
}

/// Security vulnerability information
#[derive(Debug, Clone)]
pub struct Vulnerability {
    /// Vulnerability severity (1-10)
    pub severity: u8,
    
    /// Description of the vulnerability
    pub description: String,
}

/// Scan type determining intensity and detection capabilities
#[derive(Debug, Clone)]
pub enum ScanType {
    /// Basic scan - TCP connect scan only
    Basic,
    
    /// Quick scan - common ports only
    Quick,
    
    /// Default scan - balanced scan with service detection
    Default,
    
    /// Aggressive scan - more ports, service version detection
    Aggressive,
    
    /// Comprehensive scan - all ports, deep inspection
    Comprehensive,
}

/// Network scanner for port and vulnerability detection
pub struct Scanner {
    /// Target IP or hostname
    target: String,
    
    /// Scan type/intensity
    scan_type: ScanType,
    
    /// Connection timeout in milliseconds
    timeout_ms: u64,
    
    /// Common services mapped to ports
    service_map: HashMap<u16, String>,
}

impl Scanner {
    /// Create a new scanner
    pub fn new(target: String, scan_type: ScanType) -> Self {
        let timeout_ms = match scan_type {
            ScanType::Basic => 1000,
            ScanType::Quick => 500,
            ScanType::Default => 1000,
            ScanType::Aggressive => 2000,
            ScanType::Comprehensive => 3000,
        };
        
        let mut service_map = HashMap::new();
        service_map.insert(21, "FTP".to_string());
        service_map.insert(22, "SSH".to_string());
        service_map.insert(23, "Telnet".to_string());
        service_map.insert(25, "SMTP".to_string());
        service_map.insert(53, "DNS".to_string());
        service_map.insert(80, "HTTP".to_string());
        service_map.insert(110, "POP3".to_string());
        service_map.insert(123, "NTP".to_string());
        service_map.insert(143, "IMAP".to_string());
        service_map.insert(443, "HTTPS".to_string());
        service_map.insert(445, "SMB".to_string());
        service_map.insert(3306, "MySQL".to_string());
        service_map.insert(3389, "RDP".to_string());
        service_map.insert(5432, "PostgreSQL".to_string());
        service_map.insert(8080, "HTTP-Proxy".to_string());
        
        Self {
            target,
            scan_type,
            timeout_ms,
            service_map,
        }
    }
    
    /// Scan a range of ports
    pub fn scan_ports(&self, start_port: u16, end_port: u16) -> Result<Vec<ScanResult>> {
        let mut results = Vec::new();
        
        // Resolve target to IP address
        let target_ip = match IpAddr::from_str(&self.target) {
            Ok(ip) => ip,
            Err(_) => {
                // For simplicity, we'll just use localhost if resolution fails
                // In a real scanner, you would use DNS resolution
                IpAddr::from_str("127.0.0.1").unwrap()
            }
        };
        
        // Adjust scan parameters based on scan type
        let num_threads = match self.scan_type {
            ScanType::Basic => 1,
            ScanType::Quick => 5,
            ScanType::Default => 10,
            ScanType::Aggressive => 20,
            ScanType::Comprehensive => 50,
        };
        
        // Split the port range into chunks for parallel scanning
        let ports_per_thread = (end_port - start_port + 1) / num_threads;
        let mut handles = Vec::new();
        
        for i in 0..num_threads {
            let thread_start = start_port + i * ports_per_thread;
            let thread_end = if i == num_threads - 1 {
                end_port
            } else {
                start_port + (i + 1) * ports_per_thread - 1
            };
            
            let target_ip = target_ip;
            let timeout_ms = self.timeout_ms;
            let service_map = self.service_map.clone();
            
            // Spawn a thread for each chunk of ports
            let handle = thread::spawn(move || {
                let mut thread_results = Vec::new();
                
                for port in thread_start..=thread_end {
                    // Try to connect to the port
                    let address = format!("{}:{}", target_ip, port);
                    let is_open = match TcpStream::connect_timeout(
                        &address.parse().unwrap(),
                        Duration::from_millis(timeout_ms)
                    ) {
                        Ok(mut stream) => {
                            // For some protocols, we can send a basic request to get more info
                            if port == 80 {
                                let _ = stream.write_all(b"HEAD / HTTP/1.0\r\n\r\n");
                                let mut response = [0; 1024];
                                let _ = stream.read(&mut response);
                            }
                            true
                        },
                        Err(_) => false,
                    };
                    
                    if is_open {
                        // Create a scan result for an open port
                        let service = service_map.get(&port).cloned();
                        
                        // Check for potential vulnerabilities (simplified)
                        let mut vulnerabilities = Vec::new();
                        
                        // Example vulnerability checks
                        if port == 21 {
                            vulnerabilities.push(Vulnerability {
                                severity: 7,
                                description: "FTP server may allow anonymous access".to_string(),
                            });
                        } else if port == 23 {
                            vulnerabilities.push(Vulnerability {
                                severity: 9,
                                description: "Telnet uses unencrypted communications".to_string(),
                            });
                        } else if port == 3389 {
                            vulnerabilities.push(Vulnerability {
                                severity: 6,
                                description: "RDP may be vulnerable to BlueKeep (CVE-2019-0708)".to_string(),
                            });
                        }
                        
                        thread_results.push(ScanResult {
                            port,
                            is_open,
                            protocol: Protocol::TCP, // Assuming TCP for simplicity
                            service,
                            vulnerabilities,
                        });
                    } else {
                        // Create a result for closed port
                        thread_results.push(ScanResult {
                            port,
                            is_open,
                            protocol: Protocol::TCP,
                            service: None,
                            vulnerabilities: Vec::new(),
                        });
                    }
                }
                
                thread_results
            });
            
            handles.push(handle);
        }
        
        // Collect results from all threads
        for handle in handles {
            results.extend(handle.join().unwrap());
        }
        
        // Sort results by port number
        results.sort_by_key(|r| r.port);
        
        Ok(results)
    }
} 