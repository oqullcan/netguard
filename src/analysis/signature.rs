use crate::capture::Packet;
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use anyhow::{Result, Context};
use std::fs::File;
use std::io::Read;
use std::path::Path;
use regex::Regex;

/// Represents a signature match detected in a packet
#[derive(Debug, Clone)]
pub struct SignatureMatch {
    /// The signature that matched
    pub signature: Signature,
    
    /// Offset in the packet where the match occurred
    pub offset: usize,
    
    /// Length of the matched pattern
    pub length: usize,
    
    /// Severity level of the matched signature (1-10)
    pub severity: u8,
    
    /// Description of the threat
    pub description: String,
    
    /// Signature ID that matched
    pub signature_id: String,
    
    /// Threat category
    pub category: ThreatCategory,
}

/// Threat category
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ThreatCategory {
    /// Malware detection
    Malware,
    
    /// Network attacks
    Attack,
    
    /// Data exfiltration
    Exfiltration,
    
    /// Protocol violations
    ProtocolViolation,
    
    /// Reconnaissance activity
    Reconnaissance,
    
    /// Denial of Service
    DenialOfService,
    
    /// Web attacks
    WebAttack,
    
    /// Brute force attacks
    BruteForce,
    
    /// Other threats
    Other(String),
}

/// Definition of a signature for threat detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signature {
    /// Unique identifier for the signature
    pub id: String,
    
    /// Human-readable name
    pub name: String,
    
    /// Detailed description
    pub description: String,
    
    /// Threat category
    #[serde(default = "default_category")]
    pub category: ThreatCategory,
    
    /// Severity level (1-10)
    pub severity: u8,
    
    /// Pattern to match in packets
    #[serde(skip)]
    #[serde(default)]
    pub pattern: SignaturePattern,
    
    /// JSON pattern definition
    #[serde(rename = "pattern")]
    pub pattern_def: PatternDefinition,
}

/// JSON definition of a signature pattern
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternDefinition {
    /// Protocol to match
    pub protocol: String,
    
    /// TCP flags to match (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flags: Option<Vec<String>>,
    
    /// Source port to match (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub src_port: Option<PortSpecification>,
    
    /// Destination port to match (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dst_port: Option<PortSpecification>,
    
    /// ICMP type (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub type_field: Option<u8>,
    
    /// Payload substring to match (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload_contains: Option<String>,
    
    /// Payload regex to match (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload_regex: Option<String>,
    
    /// Threshold for frequency-based detection (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threshold: Option<ThresholdConfig>,
    
    /// Timing pattern for periodic events (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timing: Option<TimingConfig>,
    
    /// Flow characteristics (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flow: Option<FlowConfig>,
}

/// Threshold for frequency-based detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThresholdConfig {
    /// Number of occurrences to trigger
    pub count: u32,
    
    /// Time window
    pub timeframe: u32,
    
    /// Time unit (seconds, minutes, etc.)
    pub unit: String,
}

/// Timing pattern for periodic events
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimingConfig {
    /// Expected interval
    pub interval: u32,
    
    /// Allowed variance
    pub variance: u32,
    
    /// Time unit (seconds, minutes, etc.)
    pub unit: String,
}

/// Flow characteristics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowConfig {
    /// Flow duration (short, medium, long)
    pub duration: String,
    
    /// Byte volume (low, medium, high)
    pub bytes: String,
}

/// Port specification (single port or port range)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PortSpecification {
    /// Single port
    SinglePort(u16),
    
    /// Multiple ports
    MultiPort(Vec<u16>),
    
    /// Port range
    Range {
        /// Start port
        start: u16,
        
        /// End port
        end: u16,
    },
}

/// Pattern types for signature matching
#[derive(Debug, Clone)]
pub enum SignaturePattern {
    /// Fixed byte sequence
    BytePattern(Vec<u8>),
    
    /// Regular expression pattern
    RegexPattern(Regex),
    
    /// Content and offset based pattern
    ContentPattern {
        content: Vec<u8>,
        offset: usize,
        depth: Option<usize>,
    },
    
    /// TCP port based pattern
    PortPattern {
        port: PortSpecification,
        is_source: bool,
    },
    
    /// Compound pattern (multiple patterns that must all match)
    CompoundPattern(Vec<SignaturePattern>),
}

// Default for SignaturePattern
impl Default for SignaturePattern {
    fn default() -> Self {
        SignaturePattern::BytePattern(Vec::new())
    }
}

/// Root structure for signature file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureDatabase {
    /// List of signatures
    pub signatures: Vec<Signature>,
}

/// Default category for serde deserialization
fn default_category() -> ThreatCategory {
    ThreatCategory::Other("unknown".to_string())
}

/// Detector for known threats using signature matching
#[derive(Debug, Clone)]
pub struct SignatureDetector {
    /// Database of signatures
    signatures: Vec<Signature>,
    
    /// Index by category for faster lookups
    category_index: HashMap<ThreatCategory, Vec<usize>>,
    
    /// Index by protocol for faster lookups
    protocol_index: HashMap<String, Vec<usize>>,
    
    /// Flow tracking for threshold-based detection
    flow_tracker: HashMap<FlowKey, FlowStats>,
}

/// Key for flow tracking
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct FlowKey {
    /// Signature ID
    signature_id: String,
    
    /// Source IP
    src_ip: Option<std::net::IpAddr>,
    
    /// Destination IP
    dst_ip: Option<std::net::IpAddr>,
}

/// Statistics for flow tracking
#[derive(Debug, Clone)]
struct FlowStats {
    /// Count of matching packets
    count: u32,
    
    /// First seen timestamp
    first_seen: std::time::Instant,
    
    /// Last seen timestamp
    last_seen: std::time::Instant,
}

impl SignatureDetector {
    /// Create a new signature detector
    pub fn new() -> Self {
        let signatures = Vec::new();
        let category_index = HashMap::new();
        let protocol_index = HashMap::new();
        let flow_tracker = HashMap::new();
        
        let mut detector = Self {
            signatures,
            category_index,
            protocol_index,
            flow_tracker,
        };
        
        // Try to load signatures from file, fall back to defaults if that fails
        if let Err(_) = detector.load_signatures_from_json_file("data/signatures/network_threats.json") {
            detector.load_default_signatures();
        }
        
        detector
    }
    
    /// Add a new signature to the detector
    pub fn add_signature(&mut self, mut signature: Signature) {
        // Convert the JSON pattern to a SignaturePattern
        signature.pattern = self.convert_pattern_def(&signature.pattern_def);
        
        let idx = self.signatures.len();
        
        // Add to category index
        let entry = self.category_index
            .entry(signature.category.clone())
            .or_insert_with(Vec::new);
        entry.push(idx);
        
        // Add to protocol index
        let protocol = signature.pattern_def.protocol.to_lowercase();
        let entry = self.protocol_index
            .entry(protocol)
            .or_insert_with(Vec::new);
        entry.push(idx);
        
        // Add the signature
        self.signatures.push(signature);
    }
    
    /// Convert PatternDefinition to SignaturePattern
    fn convert_pattern_def(&self, def: &PatternDefinition) -> SignaturePattern {
        let mut patterns = Vec::new();
        
        // Add regex pattern if defined
        if let Some(regex_str) = &def.payload_regex {
            if let Ok(regex) = Regex::new(regex_str) {
                patterns.push(SignaturePattern::RegexPattern(regex));
            }
        }
        
        // Add port pattern if defined
        if let Some(port) = &def.dst_port {
            patterns.push(SignaturePattern::PortPattern {
                port: port.clone(),
                is_source: false,
            });
        }
        
        if let Some(port) = &def.src_port {
            patterns.push(SignaturePattern::PortPattern {
                port: port.clone(),
                is_source: true,
            });
        }
        
        // Add payload contains pattern if defined
        if let Some(contains) = &def.payload_contains {
            patterns.push(SignaturePattern::ContentPattern {
                content: contains.as_bytes().to_vec(),
                offset: 0,
                depth: None,
            });
        }
        
        // If multiple patterns, create a compound pattern
        if patterns.len() > 1 {
            SignaturePattern::CompoundPattern(patterns)
        } else if patterns.len() == 1 {
            patterns.remove(0)
        } else {
            // Default byte pattern for when nothing else is specified
            SignaturePattern::BytePattern(vec![])
        }
    }
    
    /// Load signatures from a JSON file
    pub fn load_signatures_from_json_file<P: AsRef<Path>>(&mut self, path: P) -> Result<()> {
        let mut file = File::open(path).context("Failed to open signature file")?;
        let mut contents = String::new();
        file.read_to_string(&mut contents).context("Failed to read signature file")?;
        
        let database: SignatureDatabase = serde_json::from_str(&contents)
            .context("Failed to parse signature file")?;
        
        for signature in database.signatures {
            self.add_signature(signature);
        }
        
        Ok(())
    }
    
    /// Load a set of default signatures
    fn load_default_signatures(&mut self) {
        // In a real implementation, you would have a set of built-in signatures
        // Here we'll add just a few examples
        
        let example_signatures = vec![
            Signature {
                id: "SIG-001".to_string(),
                name: "Example TCP Port Scan".to_string(),
                description: "Detects TCP port scanning activity".to_string(),
                category: ThreatCategory::Reconnaissance,
                severity: 4,
                pattern: SignaturePattern::BytePattern(vec![0x45, 0x00, 0x00, 0x28]),
                pattern_def: PatternDefinition {
                    protocol: "TCP".to_string(),
                    flags: Some(vec!["SYN".to_string()]),
                    src_port: None,
                    dst_port: None,
                    type_field: None,
                    payload_contains: None,
                    payload_regex: None,
                    threshold: Some(ThresholdConfig {
                        count: 5,
                        timeframe: 10,
                        unit: "seconds".to_string(),
                    }),
                    timing: None,
                    flow: None,
                },
            },
            Signature {
                id: "SIG-002".to_string(),
                name: "Example HTTP Injection".to_string(),
                description: "Detects SQL injection attempt in HTTP traffic".to_string(),
                category: ThreatCategory::WebAttack,
                severity: 7,
                pattern: SignaturePattern::RegexPattern(Regex::new(r"SELECT\s+.*\s+FROM\s+.*").unwrap()),
                pattern_def: PatternDefinition {
                    protocol: "TCP".to_string(),
                    flags: None,
                    src_port: None,
                    dst_port: Some(PortSpecification::SinglePort(80)),
                    type_field: None,
                    payload_contains: None,
                    payload_regex: Some(r"SELECT\s+.*\s+FROM\s+.*".to_string()),
                    threshold: None,
                    timing: None,
                    flow: None,
                },
            },
        ];
        
        for signature in example_signatures {
            self.add_signature(signature);
        }
    }
    
    /// Match a packet against known signatures
    pub fn detect(&self, packet: &Packet) -> Option<SignatureMatch> {
        // Determine the protocol to check
        let protocol = match packet.protocol {
            crate::capture::Protocol::TCP => "tcp",
            crate::capture::Protocol::UDP => "udp",
            crate::capture::Protocol::ICMP => "icmp",
            crate::capture::Protocol::HTTP => "http",
            crate::capture::Protocol::HTTPS => "https",
            crate::capture::Protocol::DNS => "dns",
            _ => "unknown",
        };
        
        // Check signatures for this protocol
        if let Some(indices) = self.protocol_index.get(protocol) {
            for &idx in indices {
                let signature = &self.signatures[idx];
                
                if self.match_signature(packet, signature) {
                    // For threshold-based signatures, need to check elsewhere due to mutability
                    if signature.pattern_def.threshold.is_some() {
                        continue; // Skip threshold-based signatures for now
                    }
                    
                    return Some(SignatureMatch {
                        signature: signature.clone(),
                        offset: 0,  // Simplified implementation
                        length: 0,  // Simplified implementation
                        severity: signature.severity,
                        description: format!("{}: {}", signature.name, signature.description),
                        signature_id: signature.id.clone(),
                        category: signature.category.clone(),
                    });
                }
            }
        }
        
        // Check signatures for "any" protocol
        if let Some(indices) = self.protocol_index.get("any") {
            for &idx in indices {
                let signature = &self.signatures[idx];
                
                if self.match_signature(packet, signature) {
                    return Some(SignatureMatch {
                        signature: signature.clone(),
                        offset: 0,  // Simplified implementation
                        length: 0,  // Simplified implementation
                        severity: signature.severity,
                        description: format!("{}: {}", signature.name, signature.description),
                        signature_id: signature.id.clone(),
                        category: signature.category.clone(),
                    });
                }
            }
        }
        
        None
    }
    
    /// Check if a signature's threshold is reached 
    pub fn check_threshold(&mut self, packet: &Packet, signature_id: &str, threshold: &ThresholdConfig) -> bool {
        let flow_key = FlowKey {
            signature_id: signature_id.to_string(),
            src_ip: packet.source_ip,
            dst_ip: packet.dest_ip,
        };
        
        self.update_flow_stats(&flow_key, threshold)
    }
    
    /// Clean up old flow tracking data
    pub fn cleanup_old_flows(&mut self) {
        let now = std::time::Instant::now();
        self.flow_tracker.retain(|_, stats| {
            now.duration_since(stats.first_seen).as_secs() < 3600 // Remove entries older than 1 hour
        });
    }
    
    /// Update flow statistics and check if threshold is reached
    fn update_flow_stats(&mut self, flow_key: &FlowKey, threshold: &ThresholdConfig) -> bool {
        let now = std::time::Instant::now();
        
        // Get or create flow stats
        let stats = self.flow_tracker.entry(flow_key.clone()).or_insert_with(|| {
            FlowStats {
                count: 0,
                first_seen: now,
                last_seen: now,
            }
        });
        
        // Update stats
        stats.count += 1;
        stats.last_seen = now;
        
        // Calculate timeframe in seconds
        let timeframe_secs = match threshold.unit.as_str() {
            "seconds" => threshold.timeframe as u64,
            "minutes" => threshold.timeframe as u64 * 60,
            "hours" => threshold.timeframe as u64 * 3600,
            _ => threshold.timeframe as u64,
        };
        
        // Check if we're still within the timeframe
        let elapsed = now.duration_since(stats.first_seen).as_secs();
        
        if elapsed <= timeframe_secs {
            // Within timeframe, check if threshold is reached
            stats.count >= threshold.count
        } else {
            // Reset if outside timeframe
            stats.count = 1;
            stats.first_seen = now;
            false
        }
    }
    
    /// Match a packet against a signature
    fn match_signature(&self, packet: &Packet, signature: &Signature) -> bool {
        match &signature.pattern {
            SignaturePattern::BytePattern(pattern) => {
                self.match_byte_pattern(&packet.data.raw_data, pattern)
            },
            SignaturePattern::RegexPattern(regex) => {
                // Convert packet data to string (ignoring invalid UTF-8)
                let packet_str = String::from_utf8_lossy(&packet.data.raw_data);
                regex.is_match(&packet_str)
            },
            SignaturePattern::ContentPattern { content, offset, depth } => {
                self.match_content_pattern(&packet.data.raw_data, content, *offset, *depth)
            },
            SignaturePattern::PortPattern { port, is_source } => {
                self.match_port_pattern(packet, port, *is_source)
            },
            SignaturePattern::CompoundPattern(patterns) => {
                // All patterns must match
                patterns.iter().all(|p| {
                    match p {
                        SignaturePattern::BytePattern(pattern) => {
                            self.match_byte_pattern(&packet.data.raw_data, pattern)
                        },
                        SignaturePattern::RegexPattern(regex) => {
                            let packet_str = String::from_utf8_lossy(&packet.data.raw_data);
                            regex.is_match(&packet_str)
                        },
                        SignaturePattern::ContentPattern { content, offset, depth } => {
                            self.match_content_pattern(&packet.data.raw_data, content, *offset, *depth)
                        },
                        SignaturePattern::PortPattern { port, is_source } => {
                            self.match_port_pattern(packet, port, *is_source)
                        },
                        _ => false,
                    }
                })
            },
        }
    }
    
    /// Match a port pattern
    fn match_port_pattern(&self, packet: &Packet, port_spec: &PortSpecification, is_source: bool) -> bool {
        let port = if is_source {
            packet.source_port
        } else {
            packet.dest_port
        };
        
        match port {
            Some(port) => {
                match port_spec {
                    PortSpecification::SinglePort(p) => port == *p,
                    PortSpecification::MultiPort(ports) => ports.contains(&port),
                    PortSpecification::Range { start, end } => port >= *start && port <= *end,
                }
            },
            None => false,
        }
    }
    
    /// Match a byte pattern
    fn match_byte_pattern(&self, data: &[u8], pattern: &[u8]) -> bool {
        if pattern.is_empty() {
            return true;  // Empty pattern always matches
        }
        
        // Check if the pattern is in the data
        data.windows(pattern.len())
            .any(|window| window == pattern)
    }
    
    /// Match a content pattern
    fn match_content_pattern(&self, data: &[u8], content: &[u8], offset: usize, depth: Option<usize>) -> bool {
        // If data is too short, can't match
        if data.len() <= offset {
            return false;
        }
        
        // The portion of data to search
        let search_data = match depth {
            Some(depth) => {
                let end = std::cmp::min(offset + depth, data.len());
                &data[offset..end]
            },
            None => &data[offset..],
        };
        
        // Check if the content is in the search data
        search_data.windows(content.len())
            .any(|window| window == content)
    }
} 