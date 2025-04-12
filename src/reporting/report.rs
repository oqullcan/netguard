use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::net::IpAddr;

use crate::analysis::Threat;
use super::formats::ReportFormat;

/// Configuration for report generation
#[derive(Debug, Clone)]
pub struct ReportConfig {
    /// Output format for the report
    pub format: ReportFormat,
    
    /// Whether to include full packet data
    pub include_packet_data: bool,
    
    /// Whether to include charts and visualizations
    pub include_visualizations: bool,
    
    /// Maximum number of threats to include
    pub max_threats: Option<usize>,
    
    /// Minimum severity threshold for inclusion
    pub min_severity: Option<u8>,
}

impl Default for ReportConfig {
    fn default() -> Self {
        Self {
            format: ReportFormat::Html,
            include_packet_data: false,
            include_visualizations: true,
            max_threats: None,
            min_severity: Some(3), // Only include threats with severity >= 3
        }
    }
}

/// A security report containing threat information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    /// Report title
    pub title: String,
    
    /// Report generation timestamp
    pub timestamp: DateTime<Utc>,
    
    /// Report summary
    pub summary: ReportSummary,
    
    /// Detailed threat data
    pub threats: Vec<ThreatDetail>,
    
    /// Source and destination statistics
    pub network_stats: NetworkStats,
}

/// Summary information for the report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportSummary {
    /// Total number of threats detected
    pub total_threats: usize,
    
    /// Breakdown of threats by type
    pub threat_type_counts: HashMap<String, usize>,
    
    /// Breakdown of threats by severity
    pub severity_counts: HashMap<u8, usize>,
    
    /// Average severity across all threats
    pub average_severity: f64,
    
    /// Most common source IP
    pub most_common_source: Option<IpAddr>,
    
    /// Most common destination IP
    pub most_common_destination: Option<IpAddr>,
}

/// Detailed threat information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatDetail {
    /// Unique identifier for the threat
    pub id: u64,
    
    /// Type of the threat
    pub threat_type: String,
    
    /// Severity level (1-10)
    pub severity: u8,
    
    /// Description of the threat
    pub description: String,
    
    /// Source IP address
    pub source_ip: Option<IpAddr>,
    
    /// Destination IP address
    pub dest_ip: Option<IpAddr>,
    
    /// Timestamp when the threat was detected
    pub timestamp: DateTime<Utc>,
    
    /// Protocol information
    pub protocol: String,
    
    /// Additional metadata
    pub metadata: HashMap<String, String>,
}

/// Network-level statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkStats {
    /// Number of unique source IPs
    pub unique_sources: usize,
    
    /// Number of unique destination IPs
    pub unique_destinations: usize,
    
    /// Source IP frequency map
    pub source_frequency: HashMap<String, usize>,
    
    /// Destination IP frequency map
    pub destination_frequency: HashMap<String, usize>,
    
    /// Protocol breakdown
    pub protocol_counts: HashMap<String, usize>,
}

/// Generator for security reports
pub struct ReportGenerator {
    // Configuration could be added here
}

impl ReportGenerator {
    /// Create a new report generator
    pub fn new() -> Self {
        Self {}
    }
    
    /// Generate a report from a list of threats
    pub fn generate(&self, threats: &[Threat], config: &ReportConfig) -> Result<Report> {
        // Filter threats based on configuration
        let filtered_threats = self.filter_threats(threats, config);
        
        // Calculate network statistics
        let network_stats = self.calculate_network_stats(&filtered_threats);
        
        // Generate the report
        let report = Report {
            title: format!("NetGuard Security Report - {}", Utc::now().format("%Y-%m-%d")),
            timestamp: Utc::now(),
            summary: self.generate_summary(&filtered_threats),
            threats: filtered_threats.iter().map(|t| self.threat_to_detail(t)).collect(),
            network_stats,
        };
        
        Ok(report)
    }
    
    /// Filter threats based on configuration
    fn filter_threats<'a>(&self, threats: &'a [Threat], config: &ReportConfig) -> Vec<&'a Threat> {
        let mut filtered = threats.iter()
            .filter(|t| {
                // Apply severity filter if configured
                if let Some(min_severity) = config.min_severity {
                    if t.severity < min_severity {
                        return false;
                    }
                }
                
                true
            })
            .collect::<Vec<_>>();
        
        // Sort by severity (highest first)
        filtered.sort_by(|a, b| b.severity.cmp(&a.severity));
        
        // Apply max threats limit if configured
        if let Some(max) = config.max_threats {
            if filtered.len() > max {
                filtered.truncate(max);
            }
        }
        
        filtered
    }
    
    /// Generate summary information
    fn generate_summary(&self, threats: &[&Threat]) -> ReportSummary {
        let mut threat_type_counts = HashMap::new();
        let mut severity_counts = HashMap::new();
        let mut source_counts = HashMap::new();
        let mut dest_counts = HashMap::new();
        
        let mut total_severity = 0;
        
        for threat in threats {
            // Count threat types
            let type_name = format!("{:?}", threat.threat_type);
            *threat_type_counts.entry(type_name).or_insert(0) += 1;
            
            // Count severity levels
            *severity_counts.entry(threat.severity).or_insert(0) += 1;
            total_severity += threat.severity as usize;
            
            // Count source IPs
            if let Some(ip) = threat.associated_packet.source_ip {
                *source_counts.entry(ip).or_insert(0) += 1;
            }
            
            // Count destination IPs
            if let Some(ip) = threat.associated_packet.dest_ip {
                *dest_counts.entry(ip).or_insert(0) += 1;
            }
        }
        
        // Calculate average severity
        let average_severity = if !threats.is_empty() {
            total_severity as f64 / threats.len() as f64
        } else {
            0.0
        };
        
        // Find most common source and destination
        let most_common_source = source_counts.iter()
            .max_by_key(|(_, &count)| count)
            .map(|(ip, _)| *ip);
            
        let most_common_destination = dest_counts.iter()
            .max_by_key(|(_, &count)| count)
            .map(|(ip, _)| *ip);
        
        ReportSummary {
            total_threats: threats.len(),
            threat_type_counts,
            severity_counts,
            average_severity,
            most_common_source,
            most_common_destination,
        }
    }
    
    /// Calculate network-level statistics
    fn calculate_network_stats(&self, threats: &[&Threat]) -> NetworkStats {
        let mut source_ips = HashMap::new();
        let mut dest_ips = HashMap::new();
        let mut protocols = HashMap::new();
        
        for threat in threats {
            // Count source IPs
            if let Some(ip) = threat.associated_packet.source_ip {
                *source_ips.entry(ip.to_string()).or_insert(0) += 1;
            }
            
            // Count destination IPs
            if let Some(ip) = threat.associated_packet.dest_ip {
                *dest_ips.entry(ip.to_string()).or_insert(0) += 1;
            }
            
            // Count protocols
            let protocol = format!("{:?}", threat.associated_packet.protocol);
            *protocols.entry(protocol).or_insert(0) += 1;
        }
        
        NetworkStats {
            unique_sources: source_ips.len(),
            unique_destinations: dest_ips.len(),
            source_frequency: source_ips,
            destination_frequency: dest_ips,
            protocol_counts: protocols,
        }
    }
    
    /// Convert a threat to a detailed report entry
    fn threat_to_detail(&self, threat: &Threat) -> ThreatDetail {
        let mut metadata = HashMap::new();
        
        // Add packet size to metadata
        metadata.insert(
            "packet_size".to_string(),
            format!("{}", threat.associated_packet.size),
        );
        
        // Add packet ID to metadata
        metadata.insert(
            "packet_id".to_string(),
            format!("{}", threat.associated_packet.id),
        );
        
        ThreatDetail {
            id: threat.id,
            threat_type: format!("{:?}", threat.threat_type),
            severity: threat.severity,
            description: threat.description.clone(),
            source_ip: threat.associated_packet.source_ip,
            dest_ip: threat.associated_packet.dest_ip,
            timestamp: threat.associated_packet.timestamp,
            protocol: format!("{:?}", threat.associated_packet.protocol),
            metadata,
        }
    }
} 